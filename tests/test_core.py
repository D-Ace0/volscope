import json
import tempfile
import unittest
from pathlib import Path

from volscope.core import (command, correlate, linux_envar_rows, linux_hooks,
                           linux_kmsg_rows, linux_modules, parent_map, parse_rows, processes, timeline)
from volscope.demo import results
from volscope.storage import Case, identity


class CoreTests(unittest.TestCase):
    def test_nested_json_and_missing_values(self):
        rows = parse_rows(json.dumps([{"PID": 4, "Path": None, "__children": [{"PID": 8, "__children": []}]}]))
        self.assertEqual([r["PID"] for r in rows], [4, 8])
        self.assertIsNone(rows[0]["Path"])
        self.assertNotIn("__children", rows[0])

    def test_reject_invalid_output(self):
        for raw in ('not JSON', '{}', '[4]', '[{"__children": {}}]'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_rows(raw)

    def test_tree_cycles_missing_parent_and_pid_reuse(self):
        procs = {1: {"PPID": 2}, 2: {"PPID": 1}, 3: {"PPID": 99}, 4: {"PPID": 4},
                 5: {"PPID": 6, "CreateTime": "2025"}, 6: {"PPID": 0, "CreateTime": "2026"}}
        parents = parent_map(procs)
        self.assertIsNone(parents[3])
        self.assertIsNone(parents[4])
        self.assertIsNone(parents[5])
        for start in parents:
            seen = set()
            while start is not None:
                self.assertNotIn(start, seen)
                seen.add(start)
                start = parents[start]

    def test_correlation_and_timeline(self):
        data = results()
        metadata, network, dlls = correlate(data, 4628)
        self.assertEqual(metadata["Executable path"], "C:\\Lab\\LabSample.exe")
        self.assertIn("--training", metadata["Command line"])
        self.assertEqual(len(network), 1)
        self.assertEqual(len(dlls), 2)
        self.assertEqual(len(processes(data)), 6)
        self.assertEqual(len(timeline(data)), 7)
        self.assertEqual(correlate(data, 900)[1:], ([], []))

    def test_command_arguments_remain_separate(self):
        args = command('/tmp/my image;test.raw', 'dump_process', pid=4, output='/tmp/export dir')
        self.assertEqual(args[args.index('-f') + 1], '/tmp/my image;test.raw')
        self.assertLess(args.index('-o'), args.index('windows.pslist.PsList'))
        self.assertEqual(args[-3:], ['--pid', '4', '--dump'])
        self.assertEqual(command('a', 'dump_file', offset='0x1234', output='b')[-2:], ['--virtaddr', '0x1234'])
        with self.assertRaises(ValueError):
            command('a', 'dump_process')

    def test_linux_plugin_contract_and_normalization(self):
        args = command('/tmp/linux.raw', 'pslist', platform='linux')
        self.assertEqual(args[-1], 'linux.pslist.PsList')
        self.assertEqual(command('/tmp/linux.raw', 'dlllist', pid=42, platform='linux')[-2:], ['--pid', '42'])
        self.assertEqual(command('/tmp/linux.raw', 'dump_process', pid=42, output='/tmp/out', platform='linux')[-3:], ['--pid', '42', '--dump'])
        with self.assertRaises(ValueError):
            command('/tmp/linux.raw', 'dump_file', offset='0x1234', output='/tmp/out', platform='linux')
        linux = {
            'pslist': [{'PID': 1, 'PPID': 0, 'COMM': 'systemd', 'CREATION TIME': '2026'}],
            'pstree': [{'Pid': 42, 'Ppid': 1, 'COMM': 'bash'}],
            'cmdline': [{'PID': 42, 'ARGS': '/bin/bash -i'}],
        }
        self.assertEqual(processes(linux)[42]['ImageFileName'], 'bash')
        self.assertEqual(correlate(linux, 42)[0]['Command line'], '/bin/bash -i')

    def test_case_roundtrip_and_image_change(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / 'memory.raw'
            image.write_bytes(b'fake')
            db = Path(directory) / 'case.sqlite'
            case = Case(db)
            case.set_image(image)
            case.save('pslist', [{"PID": 4}])
            case.record('pslist', 'complete', ['-f', str(image)], '')
            case.close()

    def test_linux_rootkit_evidence_helpers(self):
        data = {
            'linux_lsmod': [{'Name': 'normal', 'Address': '0x1', 'Size': 12}],
            'linux_hidden_modules': [{'Name': 'hidden', 'Address': '0x2', 'Taints': 'O'}],
            'linux_ftrace': [{'Callback': '0xabc', 'Symbol': 'do_sys_open'}],
            'linux_tracepoints': [{'Name': 'sched_switch', 'Address': '0x3'}],
            'linux_kmsg': [{'Timestamp': 12.5, 'PID': 77, 'Message': 'module loaded'}],
            'linux_envars:77': [{'PID': 77, 'COMM': 'bash', 'Key': 'OP', 'Value': 'x'}],
        }
        modules = linux_modules(data)
        self.assertEqual(len(modules), 2)
        self.assertEqual(next(r for r in modules if r['Name'] == 'hidden')['Enumeration discrepancy'], 'Hidden scan only')
        self.assertEqual(len(linux_hooks(data)), 2)
        self.assertEqual(linux_kmsg_rows(data)[0]['Seconds'], 12.5)
        self.assertEqual(linux_envar_rows(data)[0]['KEY=VALUE'], 'OP=x')
            case = Case(db)
            self.assertEqual(case.load(), {'pslist': [{"PID": 4}]})
            self.assertEqual(case.image(), identity(image))
            image.write_bytes(b'changed')
            self.assertNotEqual(case.image(), identity(image))
            case.close()


if __name__ == '__main__':
    unittest.main()
