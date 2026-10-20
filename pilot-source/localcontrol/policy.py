"""Operator-owned configuration and conservative project-relative path policy.

This is a tool boundary, NOT a sandbox for hostile code or other host processes.
Do not allow untrusted local writers to race path checks. See SECURITY.md.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import json
import ntpath
import os
import re
import stat
from .errors import ControlError, require

DENIED_PARTS = frozenset({".git", ".codex", ".ssh", ".aws", ".azure", ".gnupg", ".npmrc", ".pypirc", ".netrc", ".git-credentials"})
SECRET_NAMES = re.compile(r"^(\.env(?:\..*)?|credentials(?:\..*)?|id_(?:rsa|ed25519)(?:\..*)?)$", re.I)
RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?$", re.I)
REPARSE = 0x400


def clean_relative(value: str, allow_empty: bool = False) -> tuple[str, ...]:
    require(isinstance(value, str), "INVALID_PATH", "Path must be text")
    require(len(value) <= 4096 and not any(ord(c) < 32 for c in value), "INVALID_PATH", "Invalid path characters")
    require(not ntpath.splitdrive(value)[0] and not value.startswith(("/", "\\")), "INVALID_PATH", "Use a project-relative path")
    parts = value.replace("\\", "/").split("/")
    if allow_empty and value in ("", "."):
        return ()
    require(all(p and p not in (".", "..") for p in parts), "INVALID_PATH", "Dot and empty path components are forbidden")
    for p in parts:
        require(not any(c in p for c in ':*?"<>|') and not p.endswith((" ", ".")), "INVALID_PATH", "Ambiguous Windows path")
        require(not RESERVED.fullmatch(p), "INVALID_PATH", "Reserved Windows filename")
        require(p.casefold() not in DENIED_PARTS and not SECRET_NAMES.fullmatch(p), "PROTECTED_PATH", "Credential or control path is protected")
    return tuple(parts)


def no_links(path: Path, allow_hardlinks: bool = False) -> None:
    """Check existing ancestors, including junctions. Missing suffix is permitted.

    allow_hardlinks is for governed host executables only: OS-serviced
    binaries under System32 are normally hard-linked into WinSxS. Project
    files keep the strict single-link rule.
    """
    parts = [*reversed(path.parents), path]
    for p in parts:
        try:
            info = p.lstat()
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & REPARSE),
                "LINK_FORBIDDEN", "Symlink/reparse paths require an explicit real root")
        if stat.S_ISREG(info.st_mode) and not allow_hardlinks:
            require(info.st_nlink == 1, "HARDLINK_FORBIDDEN", "Hard-linked files are not tool-accessible")


@dataclass(frozen=True)
class Project:
    root: Path
    writable: bool = False


@dataclass(frozen=True)
class Policy:
    projects: dict[str, Project]
    state_dir: Path
    exec_mode: str = "disabled"
    max_file_bytes: int = 262144
    max_output_bytes: int = 262144
    max_wait_ms: int = 25000
    max_timeout_ms: int = 300000
    # Throughput-first resilience profile: bounded concurrency plus backpressure.
    max_active_jobs: int = 6
    max_queued_jobs: int = 96
    min_free_memory_bytes: int = 6 * 1024 * 1024 * 1024
    # Admission floor protecting recovery headroom on the state volume: new
    # jobs defer while free space falls below this. Deliberately far above the
    # ~220MB floor observed in Release C, and job-scoped so small file
    # operations are not blanket-blocked by a large-volume threshold.
    min_free_disk_bytes: int = 10 * 1024 * 1024 * 1024
    max_ephemeral_port_fraction: float = 0.80
    ephemeral_port_start: int = 49152
    ephemeral_port_count: int = 16384
    pressure_sample_interval_ms: int = 1000
    max_job_records: int = 1000
    # Newest terminal records retained per ownership scope by explicit maintenance.
    # Capacity pressure may retain fewer when a free record slot is required.
    terminal_retention: int = 128
    max_requests: int = 10000
    # Fixed argv only. Pins and config must be outside all writable project roots.
    recipes: dict[str, dict] = field(default_factory=dict)
    workers: dict[str, dict] = field(default_factory=dict)
    # Governed shell identity: optional operator pin {executable, sha256}.
    # Discovery and enforcement live in shells.py; policy validates the shape.
    powershell: dict = field(default_factory=dict)
    max_audit_rows: int = 100000
    # Rows held back from routine admission so already-admitted work can always
    # record its mandatory completion/cancellation records.
    audit_reserve_margin: int = 256

    def __post_init__(self):
        require(self.exec_mode in {"disabled", "appcontainer"}, "INVALID_CONFIG",
                "Ownership candidate supports disabled or Windows AppContainer execution only")
        require(bool(self.projects), "INVALID_CONFIG", "At least one project must be explicitly configured")
        for name, p in self.projects.items():
            require(bool(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)), "INVALID_CONFIG", "Invalid project name")
            require(p.root.is_absolute() and p.root.is_dir(), "INVALID_CONFIG", "Project roots must be existing absolute directories")
            no_links(p.root)
            require(p.root.resolve() == p.root, "INVALID_CONFIG", "Use canonical project roots")
            require(not self.state_dir.is_relative_to(p.root), "INVALID_CONFIG", "State directory must be outside projects")
            require(not Path(__file__).resolve().is_relative_to(p.root), "INVALID_CONFIG", "Server code must be outside projects")
        if self.exec_mode == 'appcontainer':
            require(os.name == 'nt', 'PLATFORM_UNSUPPORTED', 'AppContainer cannot fall back to host execution')
            require(set(self.workers) == set(self.projects), 'SANDBOX_CONFIG', 'Every project needs a provisioned worker')
            for name, spec in self.workers.items():
                require(set(spec) == {'manifest'}, 'SANDBOX_CONFIG', 'Expected operator-owned worker manifest')
                manifest_path=Path(spec['manifest']);no_links(manifest_path)
                require(not any(manifest_path.is_relative_to(x.root) for x in self.projects.values()), 'SANDBOX_CONFIG', 'Manifest cannot be in a project')
                m=json.loads(manifest_path.read_text(encoding='utf-8'))
                require(m['workspace']==str(self.projects[name].root) and m['network_capabilities']==[], 'SANDBOX_CONFIG', 'Worker scope mismatch')
                require(m['profile_name'].startswith('LocalControl.'), 'SANDBOX_CONFIG', 'Foreign worker profile')
                runtime=Path(m['runtime']).resolve();no_links(runtime)
                require(not any(runtime.is_relative_to(x.root) or x.root.is_relative_to(runtime) for x in self.projects.values()), 'SANDBOX_CONFIG', 'Runtime must be outside workspaces')
                if m.get('python') is not None:
                    require(isinstance(m['python'], str) and m['python'], 'SANDBOX_CONFIG',
                            'Worker Python path must be text when present')
                    python=Path(m['python']).resolve();no_links(python, allow_hardlinks=True)
                    require(python.is_file() and python.is_relative_to(runtime), 'SANDBOX_CONFIG',
                            'Worker Python must be an existing file inside the worker runtime')
        roots=[p.root for p in self.projects.values()]
        require(not any(a.is_relative_to(b) or b.is_relative_to(a) for i,a in enumerate(roots) for b in roots[i+1:]),
                "INVALID_CONFIG", "Project roots must not overlap")
        require(self.state_dir.is_absolute(), "INVALID_CONFIG", "State path must be absolute")
        no_links(self.state_dir)
        for name in (
            "max_file_bytes", "max_output_bytes", "max_wait_ms", "max_timeout_ms",
            "max_active_jobs", "max_queued_jobs", "ephemeral_port_start",
            "ephemeral_port_count", "pressure_sample_interval_ms",
            "max_job_records", "terminal_retention", "max_requests", "max_audit_rows",
            "audit_reserve_margin",
        ):
            v = getattr(self, name)
            require(type(v) is int and 0 < v <= 10000000,
                    "INVALID_CONFIG", f"Invalid bound {name}")
        require(type(self.min_free_memory_bytes) is int
                and 0 < self.min_free_memory_bytes <= 1024 * 1024 * 1024 * 1024,
                "INVALID_CONFIG", "Memory headroom threshold is too large")
        require(type(self.min_free_disk_bytes) is int
                and 0 <= self.min_free_disk_bytes <= 10 * 1024 * 1024 * 1024 * 1024,
                "INVALID_CONFIG", "Disk headroom threshold is invalid")
        require(isinstance(self.max_ephemeral_port_fraction, (int, float))
                and not isinstance(self.max_ephemeral_port_fraction, bool)
                and 0.10 <= float(self.max_ephemeral_port_fraction) <= 0.99,
                "INVALID_CONFIG", "Invalid ephemeral-port pressure threshold")
        require(self.max_queued_jobs <= 4096, "INVALID_CONFIG", "At most 4096 queued jobs")
        require(1024 <= self.ephemeral_port_start <= 65535
                and 256 <= self.ephemeral_port_count <= 64512
                and self.ephemeral_port_start + self.ephemeral_port_count - 1 <= 65535,
                "INVALID_CONFIG", "Invalid ephemeral-port range")
        require(100 <= self.pressure_sample_interval_ms <= 60000,
                "INVALID_CONFIG", "Invalid pressure sample interval")
        spec = self.powershell
        require(isinstance(spec, dict) and set(spec) <= {"executable", "sha256"},
                "INVALID_CONFIG", "Unknown powershell setting")
        pinned = spec.get("executable")
        if pinned is not None:
            require(isinstance(pinned, str), "INVALID_CONFIG", "powershell.executable must be a path string")
            p = Path(pinned).resolve()
            require(p.is_absolute() and p.is_file(), "INVALID_CONFIG",
                    "Pinned shell executable must be an existing absolute file path")
            no_links(p, allow_hardlinks=True)
            require(not any(p.is_relative_to(x.root) for x in self.projects.values()),
                    "INVALID_CONFIG", "Governed executables cannot be edited through project tools")
        pinned_sha = spec.get("sha256")
        require(pinned is not None or pinned_sha is None,
                "INVALID_CONFIG", "powershell.sha256 requires a pinned executable")
        require(pinned_sha is None or (isinstance(pinned_sha, str)
                                       and bool(re.fullmatch(r"[0-9a-fA-F]{64}", pinned_sha))),
                "INVALID_CONFIG", "powershell.sha256 must be a SHA-256 hex digest")
        require(self.max_active_jobs <= 16, "INVALID_CONFIG", "At most 16 simultaneous jobs")
        require(self.max_wait_ms <= 30000 and self.max_timeout_ms <= 3600000, "INVALID_CONFIG", "Invalid time ceiling")

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        allowed = set(cls.__dataclass_fields__)
        require(not set(data) - allowed, "INVALID_CONFIG", "Unknown policy setting")
        require(isinstance(data.get("projects"), dict), "INVALID_CONFIG", "Missing projects")
        projects = {}
        for name, p in data["projects"].items():
            require(isinstance(p, dict) and not set(p) - {"root", "writable"}, "INVALID_CONFIG", "Invalid project entry")
            require(type(p.get("writable", False)) is bool, "INVALID_CONFIG", "writable must be boolean")
            projects[name] = Project(Path(p["root"]), p.get("writable", False))
        rest = {k: v for k, v in data.items() if k not in {"projects", "state_dir"}}
        return cls(projects, Path(data["state_dir"]), **rest)

    def path(self, project: str, relative: str, write: bool = False, directory: bool = False) -> Path:
        require(project in self.projects, "UNKNOWN_PROJECT", "Project is not configured")
        p = self.projects[project]
        require(not write or p.writable, "READ_ONLY", "Project is read-only")
        parts = clean_relative(relative, allow_empty=directory)
        result = p.root.joinpath(*parts)
        no_links(result)
        resolved = result.resolve()
        require(resolved.is_relative_to(p.root), "OUTSIDE_ROOT", "Path escapes project")
        # Denied/secret names were checked on caller-supplied components, but
        # Windows 8.3 short names and case aliases only expand to their real
        # names at resolve() time: recheck the canonical suffix fail-closed.
        for part in resolved.relative_to(p.root).parts:
            require(part.casefold() not in DENIED_PARTS and not SECRET_NAMES.fullmatch(part),
                    "PROTECTED_PATH", "Credential or control path is protected")
        return result

    def command(self, project: str, argv: list[str] | None, recipe: str | None) -> list[str]:
        require(project in self.projects, "UNKNOWN_PROJECT", "Project is not configured")
        require(self.exec_mode != "disabled", "EXEC_DISABLED", "Execution is disabled by operator policy")
        if recipe:
            require(not argv and recipe in self.recipes, "RECIPE_DENIED", "Unknown recipe or mixed command")
            spec = self.recipes[recipe]
            require(spec.get("project") == project, "RECIPE_DENIED", "Recipe belongs to a different project")
            pins = spec.get("sha256", {})
            require(bool(pins), "RECIPE_DENIED", "Recipes require operator-owned file hashes")
            for file, digest in pins.items():
                path = Path(file)
                require(path.is_absolute(), "RECIPE_DENIED", "Recipe pins must be absolute")
                no_links(path)
                require(not any(path.is_relative_to(p.root) for p in self.projects.values()), "RECIPE_DENIED", "Pinned code cannot be edited through project tools")
                require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, "RECIPE_CHANGED", "Pinned recipe changed")
            command = spec.get("argv")
            require(isinstance(command, list) and command and command[0] in pins, "RECIPE_DENIED", "Recipe executable must be pinned")
        else:
            require(self.exec_mode in {"trusted_local","appcontainer"}, "RECIPE_REQUIRED", "Only fixed operator-reviewed recipes are enabled")
            command = argv
        require(isinstance(command, list) and 0 < len(command) <= 100, "INVALID_COMMAND", "argv must be a nonempty list")
        require(all(isinstance(x, str) and '\0' not in x for x in command), "INVALID_COMMAND", "Invalid argv")
        require(sum(len(x) for x in command) <= 65536, "INVALID_COMMAND", "Command is too large")
        require(Path(command[0]).is_absolute() and Path(command[0]).is_file(), "INVALID_COMMAND", "Use an explicit existing executable path")
        if self.exec_mode == "appcontainer":
            manifest = json.loads(Path(self.workers[project]["manifest"]).read_text(encoding="utf-8"))
            exe_path = Path(command[0]).resolve()
            exe_name = exe_path.name.casefold()
            if exe_name in {"py.exe", "pyw.exe"}:
                worker_python_hint = manifest.get("python")
                raise ControlError(
                    "PYTHON_LAUNCHER_UNSUPPORTED",
                    "Windows py.exe may resolve to a host interpreter outside the AppContainer ACL; use the enrolled worker Python directly",
                    {"python_executable": worker_python_hint, "project": project},
                )
            if exe_name == "python.exe" and not exe_path.is_relative_to(self.projects[project].root.resolve()):
                worker_python_raw = manifest.get("python")
                require(isinstance(worker_python_raw, str) and worker_python_raw,
                        "SANDBOX_CONFIG", "Worker Python is unavailable")
                worker_python = Path(worker_python_raw).resolve()
                require(worker_python.is_file(), "SANDBOX_CONFIG", "Worker Python is unavailable")
                command = list(command)
                command[0] = str(worker_python)
        # Accidental direct termination commands denied. NOT a security boundary.
        require(Path(command[0]).name.casefold() not in {"taskkill", "taskkill.exe", "kill", "killall", "pkill", "shutdown.exe"},
                "PROTECTED_OPERATION", "Direct process/host termination is not a normal job operation")
        return list(command)
