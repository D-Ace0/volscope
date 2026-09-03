"""Synthetic evidence, intentionally distinct from a real case."""
def results():
    rows = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2026-08-20 08:00:00+00:00", "Threads": 142},
        {"PID": 480, "PPID": 4, "ImageFileName": "smss.exe", "CreateTime": "2026-08-20 08:00:01+00:00", "Threads": 2},
        {"PID": 720, "PPID": 480, "ImageFileName": "wininit.exe", "CreateTime": "2026-08-20 08:00:02+00:00", "Threads": 3},
        {"PID": 900, "PPID": 720, "ImageFileName": "services.exe", "CreateTime": "2026-08-20 08:00:03+00:00", "Threads": 8},
        {"PID": 2416, "PPID": 1800, "ImageFileName": "explorer.exe", "CreateTime": "2026-08-20 08:01:00+00:00", "Threads": 61, "Path": "C:\\Windows\\explorer.exe"},
        {"PID": 4628, "PPID": 2416, "ImageFileName": "LabSample.exe", "CreateTime": "2026-08-20 08:12:30+00:00", "Threads": 6, "Path": "C:\\Lab\\LabSample.exe"},
    ]
    return {"pslist": rows, "pstree": rows,
            "info": [{"Variable": "Source", "Value": "SYNTHETIC DEMO — no memory image analyzed"}, {"Variable": "Target", "Value": "Windows x64"}],
            "cmdline": [{"PID": 4628, "Args": '"C:\\Lab\\LabSample.exe" --training'}, {"PID": 2416, "Args": "C:\\Windows\\explorer.exe"}],
            "netscan": [{"PID": 4628, "Owner": "LabSample.exe", "Proto": "TCPv4", "LocalAddr": "192.0.2.10", "LocalPort": 49722, "ForeignAddr": "203.0.113.42", "ForeignPort": 443, "State": "ESTABLISHED", "Created": "2026-08-20 08:12:31+00:00"}],
            "dlllist:4628": [{"PID": 4628, "Name": "LabSample.exe", "Path": "C:\\Lab\\LabSample.exe", "Base": 4194304}, {"PID": 4628, "Name": "WS2_32.dll", "Path": "C:\\Windows\\System32\\WS2_32.dll", "Base": 140700000000}],
            "filescan": [{"Offset": 123456, "Name": "C:\\Lab\\LabSample.exe"}],
            "vadinfo:4628": [{"PID": 4628, "Start VPN": 4194304, "End VPN": 4259840, "Protection": "PAGE_EXECUTE_READ", "File": "C:\\Lab\\LabSample.exe"}]}
