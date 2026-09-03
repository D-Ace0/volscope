"""Cancellable QProcess queue; JSON decoding and hashing run in worker threads."""
import hashlib
import sys
from collections import deque
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QThread, Signal
from .core import command, parse_rows


class Decode(QThread):
    ready = Signal(object, str)

    def __init__(self, raw, parent=None):
        super().__init__(parent)
        self.raw = raw

    def run(self):
        try:
            self.ready.emit(parse_rows(self.raw), "")
        except Exception as exc:
            self.ready.emit([], str(exc))


class Hasher(QThread):
    ready = Signal(str)

    def __init__(self, path, parent=None):
        super().__init__(parent)
        self.path = path

    def run(self):
        try:
            before = Path(self.path).stat()
            sha1, sha256 = hashlib.sha1(), hashlib.sha256()
            with open(self.path, "rb") as stream:
                while chunk := stream.read(4 * 1024 * 1024):
                    if self.isInterruptionRequested():
                        self.ready.emit("Hash cancelled")
                        return
                    sha1.update(chunk)
                    sha256.update(chunk)
            after = Path(self.path).stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("File changed while hashing; hashes discarded")
            self.ready.emit(f"{self.path}\nSHA1: {sha1.hexdigest()}\nSHA256: {sha256.hexdigest()}")
        except Exception as exc:
            self.ready.emit(f"Hash failed: {exc}")


class Runner(QObject):
    result = Signal(str, object)
    report = Signal(str, str, object, str)
    status = Signal(str)
    busy = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.queue = deque()
        self.active = None
        self.decoder = None
        self.proc = QProcess(self)
        self.proc.readyReadStandardOutput.connect(self._stdout)
        self.proc.readyReadStandardError.connect(self._stderr)
        self.proc.finished.connect(self._finished)
        self.proc.errorOccurred.connect(self._error)
        self.cancelled = False

    def enqueue(self, image, key, pid=None, **options):
        token = f"{key}:{pid}" if pid is not None else key
        args = command(image, key, pid, **options)
        if (self.active and self.active[0] == token) or any(t[0] == token for t in self.queue):
            return
        self.queue.append((token, args))
        if self.active is None:
            self._next()

    def _next(self):
        if not self.queue:
            self.active = None
            self.busy.emit(False)
            self.status.emit("Ready")
            return
        self.active = self.queue.popleft()
        self.cancelled = False
        self.raw = bytearray()
        self.errors = bytearray()
        self.busy.emit(True)
        self.status.emit(f"Running {self.active[0]} · {len(self.queue)} queued")
        self.proc.setProgram(sys.executable)
        self.proc.setArguments(self.active[1])
        self.proc.start()

    def _stdout(self):
        self.raw.extend(bytes(self.proc.readAllStandardOutput()))

    def _stderr(self):
        self.errors.extend(bytes(self.proc.readAllStandardError()))
        self.errors = self.errors[-65536:]

    def _error(self, error):
        if error == QProcess.ProcessError.FailedToStart and self.active:
            self._complete([], self.proc.errorString())

    def _finished(self, code, exit_status):
        if self.active is None:
            return
        self._stdout()
        self._stderr()
        if self.cancelled:
            self._complete([], "Cancelled by analyst")
        elif code != 0 or exit_status == QProcess.ExitStatus.CrashExit:
            self._complete([], f"Volatility exited with code {code}")
        else:
            self.status.emit(f"Reading {self.active[0]} results")
            self.decoder = Decode(bytes(self.raw), self)
            self.decoder.ready.connect(self._complete)
            self.decoder.finished.connect(self.decoder.deleteLater)
            self.decoder.start()

    def _complete(self, rows, error):
        token, args = self.active
        if self.cancelled:
            error = "Cancelled by analyst"
        diagnostics = self.errors.decode("utf-8", errors="replace")
        self.report.emit(token, "failed" if error else "complete", args, (error + "\n" + diagnostics).strip())
        if not error:
            self.result.emit(token, rows)
        self.raw.clear()
        self.active = None
        self._next()

    def cancel(self):
        self.queue.clear()
        self.cancelled = True
        if self.proc.state() != QProcess.ProcessState.NotRunning:
            self.proc.kill()
