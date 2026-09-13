"""Cancellable QProcess queue; JSON decoding and hashing run in worker threads."""
import hashlib
import shutil
import subprocess
import sys
from collections import deque
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QThread, Signal
from .core import PLUGIN_ALIASES, PLUGINS, command, parse_rows


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


class StringScanner(QThread):
    """Stream GNU strings output and retain only literal keyword matches."""
    ready = Signal(object, str, bool)

    def __init__(self, path, keyword, minimum=4, case_sensitive=False,
                 ascii_strings=True, utf16_strings=True, limit=10000, parent=None):
        super().__init__(parent)
        self.path, self.keyword, self.minimum = path, keyword, minimum
        self.case_sensitive, self.ascii_strings = case_sensitive, ascii_strings
        self.utf16_strings, self.limit = utf16_strings, limit
        self.process = None

    def cancel(self):
        self.requestInterruption()
        if self.process and self.process.poll() is None:
            self.process.kill()

    def run(self):
        executable = shutil.which("strings")
        if not executable:
            self.ready.emit([], "The 'strings' command was not found. On Kali run: sudo apt install binutils", False)
            return
        needle = self.keyword if self.case_sensitive else self.keyword.casefold()
        rows, truncated = [], False
        modes = []
        if self.ascii_strings:
            modes.append(("ASCII", []))
        if self.utf16_strings:
            modes.append(("UTF-16LE", ["-e", "l"]))
        try:
            for encoding, mode in modes:
                if self.isInterruptionRequested():
                    self.ready.emit([], "Search cancelled", False)
                    return
                args = [executable, "-a", "-t", "x", "-n", str(self.minimum), *mode, self.path]
                self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                text=True, encoding="utf-8", errors="replace")
                for line in self.process.stdout:
                    if self.isInterruptionRequested():
                        self.process.kill()
                        self.ready.emit([], "Search cancelled", False)
                        return
                    line = line.rstrip("\r\n")
                    parts = line.lstrip().split(maxsplit=1)
                    if len(parts) != 2:
                        continue
                    value = parts[1]
                    haystack = value if self.case_sensitive else value.casefold()
                    if needle in haystack:
                        rows.append({"Offset": "0x" + parts[0], "Encoding": encoding, "String": value})
                        if len(rows) >= self.limit:
                            truncated = True
                            self.process.kill()
                            break
                stderr = self.process.stderr.read()
                code = self.process.wait()
                self.process = None
                if code not in (0, -9, 1) and not truncated:
                    raise RuntimeError(stderr.strip() or f"strings exited with code {code}")
                if truncated:
                    break
            self.ready.emit(rows, "", truncated)
        except Exception as exc:
            self.ready.emit([], str(exc), False)


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
        self.alias_attempted = set()

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
        # Volatility has renamed a few Linux plugins across releases. Retry an
        # explicit legacy alias once when the primary plugin cannot start or
        # exits without JSON, keeping the UI and case key stable.
        base_key = token.split(":", 1)[0]
        aliases = PLUGIN_ALIASES.get(base_key, ())
        if error and aliases and base_key not in self.alias_attempted and not self.cancelled:
            self.alias_attempted.add(base_key)
            replacement = aliases[0]
            retried = [replacement if value == PLUGINS[base_key].name("linux") else value for value in args]
            self.active = None
            self.queue.appendleft((token, retried))
            self._next()
            return
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
