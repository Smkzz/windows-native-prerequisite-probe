"""Runner-only safe materialization of exact inert archives; no npm/lifecycle hooks."""
import hashlib,json,os,re,tarfile,zipfile
from pathlib import Path
def need(value,reason):
    if not value:raise RuntimeError(reason)
def destination(base,relative):
    need(relative and not relative.startswith(("/", "\\")) and "\\" not in relative and
         all(p not in ("",".","..") and ":" not in p for p in relative.split("/")),"ARCHIVE_PATH_REFUSED")
    need(all(not p.endswith((" ",".")) and not any(ord(c)<32 or c in '<>"|?*' for c in p) and
             not re.fullmatch(r"(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?",p,re.I)
             for p in relative.split("/")),"WINDOWS_ARCHIVE_NAME_REFUSED")
    p=base.joinpath(*relative.split("/"))
    need(p.is_relative_to(base),"ARCHIVE_ESCAPE_REFUSED")
    return p
def put(base,relative,data,seen,budget,member_bound=32*1024**2):
    p=destination(base,relative);key=str(p).casefold()
    need(key not in seen and not p.exists(),"ARCHIVE_DUPLICATE_REFUSED");seen.add(key)
    budget[0]+=len(data);budget[1]+=1
    need(budget[0]<=512*1024**2 and budget[1]<=15000 and len(data)<=member_bound,"EXPANSION_BOUND")
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("xb") as f:f.write(data)
def prepare(root):
    need(os.name=="nt" and re.fullmatch(r"C:\\LocalControlRegressionMcp-[a-f0-9]{32}",str(root)),
         "FIXED_WINDOWS_ROOT_REQUIRED")
    m=json.loads((root/"source/REAL_WINFS_INPUTS.json").read_text())
    downloads=root/"downloads";seen=set();budget=[0,0]
    node=m["node"];archive=downloads/node["filename"]
    need(hashlib.sha256(archive.read_bytes()).hexdigest()==node["sha256"],"NODE_ARCHIVE_DRIFT")
    with zipfile.ZipFile(archive) as z:
        name=node["filename"][:-4]+"/node.exe";entry=z.getinfo(name)
        need(entry.file_size<200*1024**2,"NODE_BINARY_BOUND")
        data=z.read(entry)
        need(hashlib.sha256(data).hexdigest()==node["node_exe_sha256"],"NODE_BINARY_DRIFT")
        put(root/"node","node.exe",data,seen,budget,200*1024**2)
    upstream=root/"upstream";pins={f["path"]:f for f in m["upstream"]["files"]};found=set()
    archive=downloads/"winfs-source.tar.gz"
    need(hashlib.sha256(archive.read_bytes()).hexdigest()==m["upstream"]["sha256"],"UPSTREAM_ARCHIVE_DRIFT")
    with tarfile.open(archive,"r:gz") as t:
        for item in t:
            relative="/".join(item.name.split("/")[1:])
            if relative not in pins:continue
            need(item.isfile() and not item.issym() and not item.islnk() and item.size<=1024**2,
                 "UPSTREAM_MEMBER_REFUSED")
            data=t.extractfile(item).read()
            pin=pins[relative]
            need(relative not in found and len(data)==pin["bytes"] and hashlib.sha256(data).hexdigest()==pin["sha256"],
                 "UPSTREAM_MEMBER_DRIFT")
            found.add(relative);put(upstream,relative,data,seen,budget)
    need(found==set(pins),"UPSTREAM_SOURCE_INCOMPLETE")
    for package in sorted(m["npm"]["packages"],key=lambda p:(p["lock_path"].count("/"),p["lock_path"])):
        where=package["lock_path"]
        need(re.fullmatch(r"node_modules/(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+(?:/node_modules/(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+)*",where),
             "LOCK_PATH_REFUSED")
        archive=downloads/package["filename"]
        need(hashlib.sha256(archive.read_bytes()).hexdigest()==package["sha256"],"PACKAGE_ARCHIVE_DRIFT")
        base=destination(upstream,where);prefix=package["archive_prefix"]+"/"
        with tarfile.open(archive,"r:gz") as t:
            for item in t:
                need(not item.issym() and not item.islnk(),"PACKAGE_LINK_REFUSED")
                if item.isdir():continue
                need(item.isfile() and item.name.startswith(prefix) and item.size<=32*1024**2,"PACKAGE_MEMBER_REFUSED")
                relative=item.name[len(prefix):]
                need("node_modules" not in relative.split("/") and not relative.endswith(".node"),
                     "BUNDLED_OR_NATIVE_DEPENDENCY_REFUSED")
                put(base,relative,t.extractfile(item).read(),seen,budget)
    lock=json.loads((upstream/"package-lock.json").read_text())
    for package in m["npm"]["packages"]:
        value=json.loads((destination(upstream,package["lock_path"])/"package.json").read_text())
        need(value["name"]==package["name"] and value["version"]==package["version"] and
             lock["packages"][package["lock_path"]]["integrity"]==package["integrity"],"MATERIALIZED_PACKAGE_IDENTITY_DRIFT")
    print(json.dumps({"materialization":"PASS","upstream_files":len(pins),"exact_packages":len(m["npm"]["packages"]),
                      "expanded_files":budget[1],"expanded_bytes":budget[0],"npm_executed":False,"lifecycle_scripts":False}))
if __name__=="__main__":
    import sys
    try:
        need(len(sys.argv)==2,"FIXED_ROOT_ARGUMENT_REQUIRED");prepare(Path(sys.argv[1]))
    except BaseException as error:
        reason=str(error) if isinstance(error,RuntimeError) and re.fullmatch("[A-Z0-9_]+",str(error)) else "BOUNDED_MATERIALIZATION_EXCEPTION"
        print(json.dumps({"materialization":"FAIL","reason":reason,"error_type":type(error).__name__}));sys.exit(2)

