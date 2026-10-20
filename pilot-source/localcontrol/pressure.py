"""Low-overhead host pressure sampling for execution admission.

This module intentionally has no third-party dependencies and never shells out.
On Windows it reads memory and TCP/UDP tables through stable Win32 APIs. A
sampling failure is represented as unknown telemetry; it never crashes the
control plane.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import os
import socket
import threading
import time
from typing import Callable


_GIB = 1024 ** 3
_ERROR_INSUFFICIENT_BUFFER = 122
_AF_INET = 2
_AF_INET6 = 23
_TCP_TABLE_OWNER_PID_ALL = 5
_UDP_TABLE_OWNER_PID = 1
_MIB_TCP_STATE_CLOSE_WAIT = 8
_MIB_TCP_STATE_TIME_WAIT = 11


@dataclass(frozen=True)
class PressureSnapshot:
    sampled_ns: int
    free_memory_bytes: int | None
    tcp_total: int | None
    tcp_time_wait: int | None
    tcp_close_wait: int | None
    tcp_ephemeral_ports: int | None
    udp_ephemeral_ports: int | None
    ephemeral_port_capacity: int
    ephemeral_utilization: float | None
    free_disk_bytes: int | None
    pressured: bool
    reasons: tuple[str, ...]

    def public(self) -> dict:
        return {
            "sampled_ns": self.sampled_ns,
            "free_memory_bytes": self.free_memory_bytes,
            "tcp_total": self.tcp_total,
            "tcp_time_wait": self.tcp_time_wait,
            "tcp_close_wait": self.tcp_close_wait,
            "tcp_ephemeral_ports": self.tcp_ephemeral_ports,
            "udp_ephemeral_ports": self.udp_ephemeral_ports,
            "ephemeral_port_capacity": self.ephemeral_port_capacity,
            "ephemeral_utilization": self.ephemeral_utilization,
            "free_disk_bytes": self.free_disk_bytes,
            "pressured": self.pressured,
            "reasons": list(self.reasons),
        }


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class _MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwState", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class _MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class _MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


def _windows_free_memory() -> int | None:
    if os.name != "nt":
        return None
    try:
        status = _MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        return int(status.ullAvailPhys)
    except Exception:
        return None


def _port(value: int) -> int:
    return int(socket.ntohs(int(value) & 0xFFFF))


def _extended_table(kind: str, family: int):
    if os.name != "nt":
        return None
    try:
        api = ctypes.WinDLL("iphlpapi")
        if kind == "tcp":
            fn = api.GetExtendedTcpTable
            table_class = _TCP_TABLE_OWNER_PID_ALL
            row_type = _MIB_TCPROW_OWNER_PID if family == _AF_INET else _MIB_TCP6ROW_OWNER_PID
        else:
            fn = api.GetExtendedUdpTable
            table_class = _UDP_TABLE_OWNER_PID
            row_type = _MIB_UDPROW_OWNER_PID if family == _AF_INET else _MIB_UDP6ROW_OWNER_PID
        fn.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.BOOL,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
        ]
        fn.restype = wintypes.DWORD
        size = wintypes.ULONG(0)
        rc = int(fn(None, ctypes.byref(size), False, family, table_class, 0))
        if rc not in (0, _ERROR_INSUFFICIENT_BUFFER) or size.value < 4:
            return None
        buf = ctypes.create_string_buffer(size.value)
        rc = int(fn(buf, ctypes.byref(size), False, family, table_class, 0))
        if rc != 0:
            return None
        count = int(ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value)
        row_size = ctypes.sizeof(row_type)
        required = 4 + count * row_size
        if required > size.value:
            return None
        rows = []
        for index in range(count):
            ptr = ctypes.byref(buf, 4 + index * row_size)
            rows.append(ctypes.cast(ptr, ctypes.POINTER(row_type)).contents)
        return rows
    except Exception:
        return None


def _windows_network_snapshot(start: int, count: int) -> dict:
    end = start + count - 1
    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()
    tcp_total = 0
    time_wait = 0
    close_wait = 0
    tcp_known = False
    udp_known = False

    for family in (_AF_INET, _AF_INET6):
        rows = _extended_table("tcp", family)
        if rows is not None:
            tcp_known = True
            for row in rows:
                tcp_total += 1
                state = int(row.dwState)
                if state == _MIB_TCP_STATE_TIME_WAIT:
                    time_wait += 1
                elif state == _MIB_TCP_STATE_CLOSE_WAIT:
                    close_wait += 1
                port = _port(row.dwLocalPort)
                if start <= port <= end:
                    tcp_ports.add(port)

        rows = _extended_table("udp", family)
        if rows is not None:
            udp_known = True
            for row in rows:
                port = _port(row.dwLocalPort)
                if start <= port <= end:
                    udp_ports.add(port)

    return {
        "tcp_total": tcp_total if tcp_known else None,
        "tcp_time_wait": time_wait if tcp_known else None,
        "tcp_close_wait": close_wait if tcp_known else None,
        "tcp_ephemeral_ports": len(tcp_ports) if tcp_known else None,
        "udp_ephemeral_ports": len(udp_ports) if udp_known else None,
    }


def sample_host(
    *,
    ephemeral_port_start: int,
    ephemeral_port_count: int,
    disk_path: str | None = None,
) -> dict:
    result = {
        "free_memory_bytes": _windows_free_memory(),
        "tcp_total": None,
        "tcp_time_wait": None,
        "tcp_close_wait": None,
        "tcp_ephemeral_ports": None,
        "udp_ephemeral_ports": None,
        "free_disk_bytes": None,
    }
    if disk_path:
        try:
            import shutil
            result["free_disk_bytes"] = int(shutil.disk_usage(disk_path).free)
        except Exception:
            result["free_disk_bytes"] = None
    if os.name == "nt":
        result.update(_windows_network_snapshot(ephemeral_port_start, ephemeral_port_count))
    return result


class HostPressureMonitor:
    """Cached pressure sampler used by the execution admission path."""

    def __init__(
        self,
        *,
        min_free_memory_bytes: int,
        max_ephemeral_port_fraction: float,
        ephemeral_port_start: int,
        ephemeral_port_count: int,
        sample_interval_ms: int,
        min_free_disk_bytes: int = 0,
        disk_path: str | None = None,
        sampler: Callable[..., dict] = sample_host,
        clock_ns: Callable[[], int] = time.monotonic_ns,
    ):
        self.min_free_memory_bytes = int(min_free_memory_bytes)
        self.min_free_disk_bytes = int(min_free_disk_bytes)
        self.disk_path = disk_path
        self.max_ephemeral_port_fraction = float(max_ephemeral_port_fraction)
        self.ephemeral_port_start = int(ephemeral_port_start)
        self.ephemeral_port_count = int(ephemeral_port_count)
        self.sample_interval_ns = int(sample_interval_ms) * 1_000_000
        self.sampler = sampler
        self.clock_ns = clock_ns
        self.lock = threading.RLock()
        self.cached: PressureSnapshot | None = None

    def snapshot(self, *, force: bool = False) -> PressureSnapshot:
        now = self.clock_ns()
        with self.lock:
            if (
                not force
                and self.cached is not None
                and now - self.cached.sampled_ns < self.sample_interval_ns
            ):
                return self.cached
            try:
                raw = self.sampler(
                    ephemeral_port_start=self.ephemeral_port_start,
                    ephemeral_port_count=self.ephemeral_port_count,
                    disk_path=self.disk_path,
                )
            except Exception:
                raw = {}

            free = raw.get("free_memory_bytes")
            tcp_ports = raw.get("tcp_ephemeral_ports")
            udp_ports = raw.get("udp_ephemeral_ports")
            fractions = [
                value / self.ephemeral_port_count
                for value in (tcp_ports, udp_ports)
                if isinstance(value, int) and value >= 0
            ]
            utilization = max(fractions) if fractions else None
            reasons = []
            if isinstance(free, int) and free < self.min_free_memory_bytes:
                reasons.append("memory_headroom")
            if utilization is not None and utilization >= self.max_ephemeral_port_fraction:
                reasons.append("ephemeral_ports")
            free_disk = raw.get("free_disk_bytes")
            if (isinstance(free_disk, int) and self.min_free_disk_bytes > 0
                    and free_disk < self.min_free_disk_bytes):
                reasons.append("disk_headroom")
            snapshot = PressureSnapshot(
                sampled_ns=now,
                free_memory_bytes=free if isinstance(free, int) else None,
                tcp_total=raw.get("tcp_total") if isinstance(raw.get("tcp_total"), int) else None,
                tcp_time_wait=raw.get("tcp_time_wait") if isinstance(raw.get("tcp_time_wait"), int) else None,
                tcp_close_wait=raw.get("tcp_close_wait") if isinstance(raw.get("tcp_close_wait"), int) else None,
                tcp_ephemeral_ports=tcp_ports if isinstance(tcp_ports, int) else None,
                udp_ephemeral_ports=udp_ports if isinstance(udp_ports, int) else None,
                ephemeral_port_capacity=self.ephemeral_port_count,
                ephemeral_utilization=utilization,
                free_disk_bytes=free_disk if isinstance(free_disk, int) else None,
                pressured=bool(reasons),
                reasons=tuple(reasons),
            )
            self.cached = snapshot
            return snapshot
