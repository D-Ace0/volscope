"""Qt-independent plugin definitions, normalization, and evidence correlation."""
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Plugin:
    name: str
    title: str
    pid: bool = False


PLUGINS = {
    "info": Plugin("windows.info.Info", "Image information"),
    "pslist": Plugin("windows.pslist.PsList", "Processes"),
    "pstree": Plugin("windows.pstree.PsTree", "Process tree"),
    "cmdline": Plugin("windows.cmdline.CmdLine", "Command lines"),
    "netscan": Plugin("windows.netscan.NetScan", "Network"),
    "dlllist": Plugin("windows.dlllist.DllList", "Loaded DLLs", True),
    "filescan": Plugin("windows.filescan.FileScan", "Files"),
    "vadinfo": Plugin("windows.vadinfo.VadInfo", "Memory regions", True),
    "dump_process": Plugin("windows.pslist.PsList", "Export process executable", True),
    "dump_file": Plugin("windows.dumpfiles.DumpFiles", "Export cached file"),
}
BASELINE = ("info", "pslist", "pstree", "cmdline", "netscan")


def command(image, key, pid=None, output=None, offset=None, offline=False, symbols=None):
    spec = PLUGINS[key]
    args = ["-m", "volscope.vol_cli", "-q", "-r", "json", "-f", str(image)]
    if offline:
        args += ["--offline"]
    if symbols:
        args += ["-s", str(symbols)]
    if output:
        args += ["-o", str(output)]
    args += [spec.name]
    if pid is not None:
        if not spec.pid:
            raise ValueError("This plugin does not accept a PID")
        args += ["--pid", str(int(pid))]
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
        return int(row.get("PID"))
    except (TypeError, ValueError):
        return None


def processes(results):
    merged = {}
    for key in ("pslist", "pstree"):
        for row in results.get(key, []):
            pid = pid_of(row)
            if pid is not None:
                merged.setdefault(pid, {}).update({k: v for k, v in row.items() if v is not None})
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
    row["Command line"] = next((r.get("Args") for r in commands if r.get("Args")), row.get("Cmd", "Unavailable"))
    row["Executable path"] = row.get("Path") or row.get("Audit") or "Unavailable"
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
