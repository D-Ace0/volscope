"""Qt-independent plugin definitions, normalization, and evidence correlation."""
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Plugin:
    title: str
    pid: bool = False
    names: dict | None = None
    pid_args: dict | None = None

    def name(self, platform):
        value = (self.names or {}).get(platform)
        if not value:
            raise ValueError(f"{self.title} is not available for {platform.title()} images")
        return value

    def pid_arg(self, platform):
        return (self.pid_args or {}).get(platform, "--pid")


PLUGINS = {
    "detect_linux": Plugin("Linux detection", names={"linux": "banners.Banners"}),
    "detect_windows": Plugin("Windows detection", names={"windows": "windows.info.Info"}),
    "info": Plugin("Image information", names={"windows": "windows.info.Info", "linux": "banners.Banners"}),
    "pslist": Plugin("Processes", names={"windows": "windows.pslist.PsList", "linux": "linux.pslist.PsList"}),
    "pstree": Plugin("Process tree", names={"windows": "windows.pstree.PsTree", "linux": "linux.pstree.PsTree"}),
    "cmdline": Plugin("Command lines", names={"windows": "windows.cmdline.CmdLine", "linux": "linux.psaux.PsAux"}),
    "netscan": Plugin("Network", names={"windows": "windows.netscan.NetScan", "linux": "linux.sockstat.Sockstat"},
                       pid_args={"linux": "--pids"}),
    "dlllist": Plugin("Loaded libraries", True,
                      {"windows": "windows.dlllist.DllList", "linux": "linux.elfs.Elfs"}),
    "filescan": Plugin("Files", names={"windows": "windows.filescan.FileScan", "linux": "linux.lsof.Lsof"}),
    "vadinfo": Plugin("Memory regions", True, {"windows": "windows.vadinfo.VadInfo", "linux": "linux.proc.Maps"}),
    "dump_process": Plugin("Export process executable", True,
                           {"windows": "windows.pslist.PsList", "linux": "linux.pslist.PsList"}),
    "dump_file": Plugin("Export cached file", names={"windows": "windows.dumpfiles.DumpFiles"}),
}
BASELINE = ("info", "pslist", "pstree", "cmdline", "netscan")


def command(image, key, pid=None, output=None, offset=None, offline=False, symbols=None, platform="windows"):
    spec = PLUGINS[key]
    args = ["-m", "volscope.vol_cli", "-q", "-r", "json", "-f", str(image)]
    if offline:
        args += ["--offline"]
    if symbols:
        args += ["-s", str(symbols)]
    if output:
        args += ["-o", str(output)]
    args += [spec.name(platform)]
    if pid is not None:
        if not spec.pid:
            raise ValueError("This plugin does not accept a PID")
        args += [spec.pid_arg(platform), str(int(pid))]
    if key == "dump_process":
        if pid is None or not output:
            raise ValueError("Select a process and export directory")
        args += ["--dump"]
    if key == "dump_file":
        if offset is None or not output:
            raise ValueError("Select a file object and export directory")
        args += ["--virtaddr", hex(int(str(offset), 0) if isinstance(offset, str) else offset)]
    return args


def parse_rows(raw):
    """Strict JSON input; flatten Volatility TreeGrid's nested __children nodes."""
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("Expected Volatility JSON renderer output (an array)")
    rows, stack = [], list(reversed(data))
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            raise ValueError("Invalid result row")
        children = node.get("__children", [])
        if not isinstance(children, list):
            raise ValueError("Invalid child rows")
        rows.append({k: v for k, v in node.items() if k != "__children"})
        stack.extend(reversed(children))
    return rows


def pid_of(row):
    try:
        return int(next((row[key] for key in ("PID", "Pid", "pid") if row.get(key) is not None), None))
    except (TypeError, ValueError):
        return None


def processes(results):
    merged = {}
    for key in ("pslist", "pstree"):
        for row in results.get(key, []):
            pid = pid_of(row)
            if pid is not None:
                normalized = {k: v for k, v in row.items() if v is not None}
                normalized["PID"] = pid
                normalized["PPID"] = normalized.get("PPID", normalized.get("Ppid"))
                normalized["ImageFileName"] = normalized.get("ImageFileName") or normalized.get("COMM") or normalized.get("Process") or "Unknown"
                normalized["CreateTime"] = normalized.get("CreateTime") or normalized.get("CREATION TIME")
                merged.setdefault(pid, {}).update(normalized)
    return merged


def parent_map(procs):
    """Break cycles and orphan missing/reused parents rather than losing rows."""
    parents = {}
    for pid, row in procs.items():
        try:
            parent = int(row.get("PPID"))
        except (TypeError, ValueError):
            parent = None
        if parent not in procs or parent == pid:
            parent = None
        if parent is not None:
            child_time, parent_time = row.get("CreateTime"), procs[parent].get("CreateTime")
            if child_time and parent_time and str(parent_time) > str(child_time):
                parent = None
        parents[pid] = parent
    for pid in parents:
        seen, current = {pid}, parents[pid]
        while current is not None:
            if current in seen:
                parents[pid] = None
                break
            seen.add(current)
            current = parents.get(current)
    return parents


def correlate(results, pid):
    row = dict(processes(results).get(pid, {}))
    commands = [r for r in results.get("cmdline", []) if pid_of(r) == pid]
    command_keys = ("Args", "ARGS", "Command", "COMMAND", "Cmdline")
    row["Command line"] = next((r.get(key) for r in commands for key in command_keys if r.get(key)), row.get("Cmd", "Unavailable"))
    path_keys = ("Path", "Audit", "EXE", "Executable", "File Path")
    row["Executable path"] = next((row.get(key) for key in path_keys if row.get(key) and str(row.get(key)).lower() not in ("disabled", "unavailable")), "Unavailable")
    return row, [r for r in results.get("netscan", []) if pid_of(r) == pid], results.get(f"dlllist:{pid}", [])


def timeline(results):
    events = []
    for row in processes(results).values():
        for field, event in (("CreateTime", "Process created"), ("ExitTime", "Process exited")):
            if row.get(field):
                events.append({"Time": row[field], "Event": event, "PID": row.get("PID"), "Name": row.get("ImageFileName"), "Source": "pslist/pstree"})
    for row in results.get("netscan", []):
        if row.get("Created"):
            events.append({"Time": row["Created"], "Event": "Network object created", "PID": row.get("PID"), "Name": row.get("Owner"), "Source": "netscan"})
    return sorted(events, key=lambda r: str(r["Time"]))
