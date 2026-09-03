"""Headless integration tests: QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests."""
import hashlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer
from volscope.app import MainWindow
from volscope.runner import Hasher, Runner

APP = QApplication.instance() or QApplication([])


def wait_for(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while not predicate() and time.monotonic() < deadline:
        APP.processEvents()
        time.sleep(.005)
    if not predicate():
        raise AssertionError('Timed out waiting for Qt job')


class QtTests(unittest.TestCase):
    def test_demo_selection_and_sections(self):
        window = MainWindow(demo=True)
        window.show()
        APP.processEvents()
        self.assertEqual(window.pages.count(), 8)
        self.assertEqual(window.pid, 4628)
        self.assertIn('LabSample.exe', window.metadata.toPlainText())
        self.assertEqual(window.pid_network.proxy.rowCount(), 1)
        self.assertEqual(window.pid_dlls.proxy.rowCount(), 2)
        window.select_pid(900)
        self.assertEqual(window.pid_network.proxy.rowCount(), 0)
        window.filter_tree('LabSample')
        window.close()

    def test_background_success_failure_and_queue(self):
        runner = Runner()
        delivered, reports, ticks = [], [], []
        runner.result.connect(lambda key, rows: delivered.append((key, rows)))
        runner.report.connect(lambda *args: reports.append(args))
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.append(1))
        timer.start(10)
        runner.queue.extend([
            ('good', ['-c', 'import time; time.sleep(.2); print(\'[ {"PID": 4, "__children": []} ]\')']),
            ('bad', ['-c', 'import sys; print("symbol error",file=sys.stderr); sys.exit(2)']),
            ('malformed', ['-c', 'print("not JSON")']),
        ])
        runner._next()
        wait_for(lambda: runner.active is None)
        timer.stop()
        self.assertEqual(delivered, [('good', [{'PID': 4}])])
        self.assertEqual([r[1] for r in reports], ['complete', 'failed', 'failed'])
        self.assertIn('symbol error', reports[1][3])
        self.assertGreater(len(ticks), 5)

    def test_cancellation_drops_queue(self):
        runner = Runner()
        reports = []
        runner.report.connect(lambda *args: reports.append(args))
        runner.queue.extend([('slow', ['-c', 'import time; time.sleep(30)']), ('never', ['-c', 'print("[]")'])])
        runner._next()
        QTimer.singleShot(50, runner.cancel)
        wait_for(lambda: runner.active is None)
        self.assertEqual(len(reports), 1)
        self.assertIn('Cancelled', reports[0][3])

    def test_streaming_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'artifact.bin'
            path.write_bytes(b'abc')
            worker = Hasher(str(path))
            messages = []
            worker.ready.connect(messages.append)
            worker.start()
            wait_for(lambda: bool(messages) and not worker.isRunning())
            self.assertIn(hashlib.sha1(b'abc').hexdigest(), messages[0])
            self.assertIn(hashlib.sha256(b'abc').hexdigest(), messages[0])


if __name__ == '__main__':
    unittest.main()
