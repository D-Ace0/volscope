"""Native Qt analyst workspace. Plugin execution is isolated in a subprocess."""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QSortFilterProxyModel, QThread
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QListWidget, QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton,
    QSpinBox, QSplitter, QStackedWidget, QTabWidget, QTableView, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)
from .core import BASELINE, PLUGINS, correlate, parent_map, pid_of, processes, timeline
from .demo import results as demo_results
from .runner import Hasher, Runner, StringScanner
from .storage import Case, identity


class RowsModel(QAbstractTableModel):
    def __init__(self, rows=None, parent=None):
        super().__init__(parent)
        self.rows = rows or []
        self.columns = list(dict.fromkeys(k for row in self.rows for k in row))

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if index.isValid() and role == Qt.ItemDataRole.EditRole:
            value = self.rows[index.row()].get(self.columns[index.column()])
            return "" if value is None else str(value)
        if index.isValid() and role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            value = self.rows[index.row()].get(self.columns[index.column()])
            return "—" if value is None else str(value)
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section]
        return None


def enable_field_copy(view):
    """Copy the focused cell, or the cell under a context-menu request."""
    def copy_value():
        index = view.currentIndex()
        if index.isValid():
            value = index.data(Qt.ItemDataRole.EditRole)
            QApplication.clipboard().setText("" if value is None else str(value))

    action = QAction("Copy value", view)
    action.setShortcuts(QKeySequence.StandardKey.Copy)
    action.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
    action.triggered.connect(copy_value)
    view.addAction(action)
    view.setToolTip("Select a field and press Ctrl+C, or right-click to copy its value.")

    def show_menu(position):
        index = view.indexAt(position)
        if not index.isValid():
            return
        view.setCurrentIndex(index)
        menu = QMenu(view)
        menu.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        menu.addAction(action)
        menu.popup(view.viewport().mapToGlobal(position))

    view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    view.customContextMenuRequested.connect(show_menu)


class EvidenceTable(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.search = QLineEdit(placeholderText="Filter evidence across all columns…")
        self.count = QLabel("No results loaded")
        layout.addWidget(self.search)
        layout.addWidget(self.count)
        self.view = QTableView()
        self.view.setSelectionBehavior(QTableView.SelectionBehavior.SelectItems)
        self.view.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.view.setSortingEnabled(True)
        self.view.setWordWrap(False)
        self.view.verticalHeader().hide()
        self.view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.view.setModel(self.proxy)
        enable_field_copy(self.view)
        self.search.textChanged.connect(self.proxy.setFilterFixedString)
        layout.addWidget(self.view)
        self.set_rows([])

    def set_rows(self, rows):
        old = self.proxy.sourceModel()
        self.proxy.setSourceModel(RowsModel(rows, self))
        if old:
            old.deleteLater()
        self.count.setText(f"{len(rows):,} evidence rows" if rows else "No rows loaded · run the relevant analysis to distinguish empty results")
        for col in range(min(20, self.proxy.columnCount())):
            self.view.setColumnWidth(col, 165)

    def selected(self, index=None):
        index = index if index is not None else self.view.currentIndex()
        source = self.proxy.mapToSource(index)
        return self.proxy.sourceModel().rows[source.row()] if source.isValid() else {}


STYLE = """
QWidget { background: #101823; color: #dce7f2; font-family: 'Segoe UI', 'DejaVu Sans'; font-size: 13px; }
QMainWindow { background: #101823; }
QPushButton { background: #203247; border: 1px solid #354c62; border-radius: 5px; padding: 8px 12px; }
QPushButton:hover { background: #2b455e; }
QPushButton:disabled { color: #607286; background: #172330; }
QPushButton#primary { background: #117e80; color: white; border: none; }
QLineEdit { background: #172330; border: 1px solid #304358; border-radius: 4px; padding: 8px; }
QListWidget, QTreeWidget, QTableView, QPlainTextEdit { background: #131f2d; border: 1px solid #26384b; selection-background-color: #225b70; }
QListWidget::item { padding: 12px; }
QHeaderView::section { background: #203044; padding: 8px; border: none; }
QTabBar::tab { background: #203044; padding: 9px; }
QTabBar::tab:selected { background: #225b70; }
QLabel#title { font-size: 25px; font-weight: 600; color: #f0f7fc; }
QLabel#subtitle { color: #86a6bc; }
QSplitter::handle { background: #26384b; }
"""


class MainWindow(QMainWindow):
    def __init__(self, demo=False):
        super().__init__()
        self.setWindowTitle("VolScope · Memory Investigation")
        self.resize(1440, 900)
        self.results, self.case, self.image, self.pid = {}, None, None, None
        self.demo = False
        self.hash_worker = self.string_worker = None
        self.runner = Runner(self)
        self.runner.result.connect(self.on_result)
        self.runner.report.connect(self.on_report)
        self.runner.busy.connect(self.on_busy)
        self.runner.status.connect(self.statusBar().showMessage)
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 16, 20, 12)
        title = QLabel("VOLSCOPE   /   Memory Investigation")
        title.setObjectName("title")
        layout.addWidget(title)
        self.case_label = QLabel("Open a memory image or explore the synthetic demo")
        self.case_label.setObjectName("subtitle")
        layout.addWidget(self.case_label)
        bar = QHBoxLayout()
        self.open_button = self.button(bar, "Open memory image", self.open_image, True)
        self.case_button = self.button(bar, "Open case", self.open_case)
        self.demo_button = self.button(bar, "Explore demo", self.load_demo)
        self.run_button = self.button(bar, "Run baseline", self.baseline)
        self.cancel_button = self.button(bar, "Cancel analysis", self.cancel_work)
        self.button(bar, "SHA1 / SHA256", self.hash_file)
        bar.addStretch()
        layout.addLayout(bar)
        options = QHBoxLayout()
        self.offline = QCheckBox("Offline symbols")
        options.addWidget(self.offline)
        self.symbols = QLineEdit(placeholderText="Optional symbol directory")
        self.symbols.setMaximumWidth(420)
        options.addWidget(self.symbols)
        options.addStretch()
        layout.addLayout(options)
        split = QSplitter()
        self.nav = QListWidget()
        self.sections = ["Overview", "Processes", "Process Tree", "Network", "Files", "Memory Regions", "DLLs", "Timeline", "Strings Search"]
        self.nav.addItems(self.sections)
        self.nav.setMaximumWidth(185)
        split.addWidget(self.nav)
        self.pages = QStackedWidget()
        split.addWidget(self.pages)
        self.tables = {}
        for section in self.sections:
            page = QWidget()
            page_layout = QVBoxLayout(page)
            heading = QLabel(section)
            heading.setObjectName("title")
            page_layout.addWidget(heading)
            if section == "Overview":
                self.overview = QPlainTextEdit()
                self.overview.setReadOnly(True)
                page_layout.addWidget(self.overview)
            elif section == "Strings Search":
                note = QLabel("Search printable strings in the current raw memory image. Keyword matching is literal, like grep -F.")
                note.setWordWrap(True)
                page_layout.addWidget(note)
                controls = QHBoxLayout()
                self.strings_keyword = QLineEdit(placeholderText="Keyword, domain, IP address, path, command, or flag…")
                self.strings_keyword.returnPressed.connect(self.search_strings)
                controls.addWidget(self.strings_keyword, 1)
                self.strings_minimum = QSpinBox()
                self.strings_minimum.setRange(3, 100)
                self.strings_minimum.setValue(4)
                self.strings_minimum.setPrefix("Minimum length: ")
                controls.addWidget(self.strings_minimum)
                self.strings_limit = QSpinBox()
                self.strings_limit.setRange(100, 100000)
                self.strings_limit.setValue(10000)
                self.strings_limit.setSingleStep(1000)
                self.strings_limit.setPrefix("Max results: ")
                controls.addWidget(self.strings_limit)
                page_layout.addLayout(controls)
                options = QHBoxLayout()
                self.strings_case = QCheckBox("Case sensitive")
                self.strings_ascii = QCheckBox("ASCII")
                self.strings_ascii.setChecked(True)
                self.strings_utf16 = QCheckBox("UTF-16LE")
                self.strings_utf16.setChecked(True)
                options.addWidget(self.strings_case)
                options.addWidget(self.strings_ascii)
                options.addWidget(self.strings_utf16)
                self.strings_button = self.button(options, "Search memory", self.search_strings, True)
                options.addStretch()
                page_layout.addLayout(options)
                self.strings_table = EvidenceTable()
                page_layout.addWidget(self.strings_table)
            elif section == "Process Tree":
                search = QLineEdit(placeholderText="Find process or PID (matching branches stay visible)")
                search.textChanged.connect(self.filter_tree)
                page_layout.addWidget(search)
                buttons = QHBoxLayout()
                self.button(buttons, "Expand all", lambda: self.tree.expandAll())
                self.button(buttons, "Collapse all", lambda: self.tree.collapseAll())
                page_layout.addLayout(buttons)
                self.tree = QTreeWidget()
                self.tree.setHeaderLabels(["Process", "PID", "PPID", "Created"])
                self.tree.setColumnWidth(0, 260)
                self.tree.setSelectionBehavior(QTreeWidget.SelectionBehavior.SelectItems)
                enable_field_copy(self.tree)
                self.tree.itemSelectionChanged.connect(self.tree_selected)
                page_layout.addWidget(self.tree)
            else:
                if section in ("Files", "Memory Regions", "DLLs"):
                    actions = QHBoxLayout()
                    key = {"Files": "filescan", "Memory Regions": "vadinfo", "DLLs": "dlllist"}[section]
                    self.button(actions, "Load " + section.lower(), lambda checked=False, k=key: self.run_plugin(k))
                    if section == "Files":
                        self.button(actions, "Export selected cached file", self.dump_file)
                    page_layout.addLayout(actions)
                table = EvidenceTable()
                self.tables[section] = table
                if section in ("Processes", "Network", "DLLs", "Memory Regions", "Timeline"):
                    table.view.clicked.connect(lambda index, t=table: self.select_table_pid(t, index))
                page_layout.addWidget(table)
            self.pages.addWidget(page)
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.nav.setCurrentRow(0)
        detail = QWidget()
        detail.setMinimumWidth(330)
        dl = QVBoxLayout(detail)
        self.selection_label = QLabel("PROCESS INSPECTOR")
        dl.addWidget(self.selection_label)
        self.details = QTabWidget()
        self.metadata = QPlainTextEdit()
        self.metadata.setReadOnly(True)
        self.details.addTab(self.metadata, "Metadata")
        self.pid_network, self.pid_dlls = EvidenceTable(), EvidenceTable()
        self.details.addTab(self.pid_network, "Network")
        self.details.addTab(self.pid_dlls, "DLLs")
        dl.addWidget(self.details)
        self.button(dl, "Load DLLs for selected PID", lambda: self.run_plugin("dlllist"))
        self.button(dl, "Load memory regions for PID", lambda: self.run_plugin("vadinfo"))
        self.button(dl, "Export process executable (PE)", self.dump_process)
        note = QLabel("PID links are investigative leads. PID reuse and stale network objects can affect correlation.")
        note.setWordWrap(True)
        note.setObjectName("subtitle")
        dl.addWidget(note)
        split.addWidget(detail)
        split.setSizes([175, 800, 400])
        layout.addWidget(split, 1)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(125)
        self.log.document().setMaximumBlockCount(1000)
        self.log.setPlaceholderText("Analysis activity and diagnostics appear here")
        layout.addWidget(self.log)
        self.setCentralWidget(root)
        self.on_busy(False)
        self.refresh()
        if demo:
            self.load_demo()

    def cancel_work(self):
        self.runner.cancel()
        if self.string_worker and self.string_worker.isRunning():
            self.string_worker.cancel()

    def button(self, layout, text, slot, primary=False):
        button = QPushButton(text)
        if primary:
            button.setObjectName("primary")
        button.clicked.connect(slot)
        layout.addWidget(button)
        return button

    def error(self, message):
        QMessageBox.warning(self, "VolScope", str(message))

    def on_busy(self, busy):
        for button in (self.open_button, self.case_button, self.demo_button, self.run_button):
            button.setEnabled(not busy)
        strings_busy = bool(self.string_worker and self.string_worker.isRunning())
        self.cancel_button.setEnabled(busy or strings_busy)

    def reset(self):
        if self.case:
            self.case.close()
        self.case = None
        self.results, self.image, self.pid, self.demo = {}, None, None, False
        self.log.clear()

    def open_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Windows memory image", "", "Memory images (*.raw *.mem *.dmp *.vmem *.bin);;All files (*)")
        if not path:
            return
        folder = QFileDialog.getExistingDirectory(self, "Choose parent folder for a new case")
        if not folder:
            return
        new_case = None
        try:
            identity(path)
            directory = Path(folder) / ("volscope-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
            directory.mkdir()
            new_case = Case(directory / "case.sqlite")
            new_case.set_image(path)
        except Exception as exc:
            if new_case:
                new_case.close()
            self.error(exc)
            return
        self.reset()
        self.case, self.image = new_case, str(Path(path).resolve())
        self.case_label.setText(f"{Path(path).name}   ·   {directory}")
        self.refresh()
        self.baseline()

    def open_case(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open case", "", "VolScope case (*.sqlite)")
        if not path:
            return
        case = None
        try:
            case = Case(path)
            stored, data = case.image(), case.load()
            if not stored:
                raise ValueError("This database has no VolScope image metadata")
            valid = False
            try:
                valid = identity(stored["path"]) == stored
            except OSError:
                pass
        except Exception as exc:
            if case:
                case.close()
            self.error(exc)
            return
        self.reset()
        self.case, self.results = case, data
        self.image = stored["path"] if valid else None
        self.case_label.setText(f"{Path(path).parent.name} · {'Cached case' if valid else 'Cached results only — original image missing or changed'}")
        self.refresh()

    def load_demo(self):
        self.reset()
        self.demo = True
        self.results = demo_results()
        self.case_label.setText("SYNTHETIC DEMO   ·   Training evidence only · No image analyzed")
        self.refresh()
        self.nav.setCurrentRow(2)
        self.select_pid(4628)

    def baseline(self):
        if not self.ensure_image():
            return
        for key in BASELINE:
            self.run_plugin(key)

    def ensure_image(self):
        if not self.image:
            self.error("Open a memory image to run analysis. Demo and detached cached cases are view-only.")
            return False
        try:
            if self.case and identity(self.image) != self.case.image():
                raise ValueError("Image changed since this case was created. Open it as a new case.")
        except Exception as exc:
            self.error(exc)
            return False
        return True

    def run_plugin(self, key, **kwargs):
        if not self.ensure_image():
            return
        pid = self.pid if PLUGINS[key].pid else None
        if PLUGINS[key].pid and pid is None:
            self.error("Select a process first")
            return
        try:
            self.runner.enqueue(self.image, key, pid, offline=self.offline.isChecked(), symbols=self.symbols.text().strip() or None, **kwargs)
        except Exception as exc:
            self.error(exc)

    def on_result(self, key, rows):
        self.results[key] = rows
        if key.startswith("dump_"):
            self.log.appendPlainText("Artifact recovery results:\n" + json.dumps(rows, indent=2, ensure_ascii=False))
        if self.case:
            try:
                self.case.save(key, rows)
            except Exception as exc:
                self.error(f"Results available in memory, but case save failed: {exc}")
        self.refresh()

    def on_report(self, key, status, args, diagnostics):
        self.log.appendPlainText(f"{key}: {status}\n{diagnostics}")
        if self.case:
            try:
                self.case.record(key, status, args, diagnostics)
            except Exception as exc:
                self.log.appendPlainText(f"Could not save run history: {exc}")

    def refresh(self):
        procs = processes(self.results)
        self.overview.setPlainText(
            f"{'SYNTHETIC DEMO' if self.demo else 'CASE OVERVIEW'}\n\n"
            f"Processes: {len(procs):,}\nNetwork objects: {len(self.results.get('netscan', [])):,}\n"
            f"Completed result sets: {len(self.results)}\n\n"
            "Workflow\n1. Open a Windows memory image.\n2. Review the process tree and select a PID.\n"
            "3. Inspect metadata and network evidence; load DLLs on demand.\n"
            "4. Load files or memory regions as needed, then export artifacts.\n\n"
            "Sections show collected evidence, not a clean bill of health. Failed plugins are recorded below.\n"
            "Timeline combines available process and network timestamps; it is not a complete system timeline.\n\n"
            + "Image information\n" + json.dumps(self.results.get("info", []), indent=2, ensure_ascii=False))
        self.tables["Processes"].set_rows(list(procs.values()))
        self.tables["Network"].set_rows(self.results.get("netscan", []))
        self.tables["Files"].set_rows(self.results.get("filescan", []))
        self.tables["Timeline"].set_rows(timeline(self.results))
        self.tree.blockSignals(True)
        self.tree.clear()
        nodes = {pid: QTreeWidgetItem([str(r.get("ImageFileName", "Unknown")), str(pid), str(r.get("PPID", "")), str(r.get("CreateTime", ""))]) for pid, r in procs.items()}
        for pid, parent in parent_map(procs).items():
            nodes[pid].setData(0, Qt.ItemDataRole.UserRole, pid)
            if parent is None:
                self.tree.addTopLevelItem(nodes[pid])
            else:
                nodes[parent].addChild(nodes[pid])
        self.tree.expandToDepth(2)
        if self.pid in nodes:
            self.tree.setCurrentItem(nodes[self.pid])
        self.tree.blockSignals(False)
        self.select_pid(self.pid)

    def filter_tree(self, text):
        # Iterative postorder avoids recursion limits on malformed/deep evidence.
        stack = [(self.tree.topLevelItem(i), False) for i in range(self.tree.topLevelItemCount())]
        while stack:
            node, visited = stack.pop()
            if not visited:
                stack.append((node, True))
                stack.extend((node.child(i), False) for i in range(node.childCount()))
                continue
            match = text.casefold() in (node.text(0) + " " + node.text(1)).casefold()
            visible = match or any(not node.child(i).isHidden() for i in range(node.childCount()))
            node.setHidden(not visible)
            if text and visible:
                node.setExpanded(True)

    def tree_selected(self):
        items = self.tree.selectedItems()
        if items:
            self.select_pid(items[0].data(0, Qt.ItemDataRole.UserRole))

    def select_table_pid(self, table, index):
        pid = pid_of(table.selected(index))
        # Keep the clicked cell focused when inspecting the already-selected PID.
        if pid != self.pid:
            self.select_pid(pid)

    def select_pid(self, pid):
        self.pid = pid
        if pid is None:
            self.selection_label.setText("PROCESS INSPECTOR · Select a process")
            self.metadata.setPlainText("Select a row or a process-tree node to correlate evidence.")
            network, dlls = [], []
        else:
            metadata, network, dlls = correlate(self.results, pid)
            self.selection_label.setText(f"PID {pid}  ·  {metadata.get('ImageFileName', 'Unknown process')}")
            ordered = {key: metadata[key] for key in ("Executable path", "Command line", "PID", "PPID", "CreateTime") if key in metadata}
            ordered.update(metadata)
            self.metadata.setPlainText("\n\n".join(f"{key}\n{value}" for key, value in ordered.items()))
        self.pid_network.set_rows(network)
        self.pid_dlls.set_rows(dlls)
        self.tables["DLLs"].set_rows(dlls)
        self.tables["Memory Regions"].set_rows(self.results.get(f"vadinfo:{pid}", []))

    def export_directory(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose parent directory for recovered artifacts")
        if folder:
            destination = Path(folder) / ("export-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
            destination.mkdir()
            self.log.appendPlainText(f"Export destination: {destination}")
            return str(destination)
        return None

    def dump_process(self):
        if not self.ensure_image():
            return
        if self.pid is None:
            self.error("Select a process first")
            return
        try:
            output = self.export_directory()
            if output:
                self.run_plugin("dump_process", output=output)
        except Exception as exc:
            self.error(exc)

    def dump_file(self):
        if not self.ensure_image():
            return
        row = self.tables["Files"].selected()
        offset = row.get("Offset")
        if offset is None:
            self.error("Load Files and select a file object with a virtual Offset first")
            return
        try:
            output = self.export_directory()
            if output:
                self.run_plugin("dump_file", offset=offset, output=output)
        except Exception as exc:
            self.error(exc)

    def hash_file(self):
        if self.hash_worker and self.hash_worker.isRunning():
            self.error("A hash calculation is already running")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Select image or exported artifact to hash")
        if path:
            self.log.appendPlainText(f"Calculating hashes: {path}")
            self.hash_worker = Hasher(path, self)
            self.hash_worker.ready.connect(self.log.appendPlainText)
            self.hash_worker.start()

    def search_strings(self):
        if not self.ensure_image():
            return
        keyword = self.strings_keyword.text()
        if not keyword:
            self.error("Enter a keyword to search for")
            return
        if not (self.strings_ascii.isChecked() or self.strings_utf16.isChecked()):
            self.error("Select ASCII, UTF-16LE, or both")
            return
        if self.string_worker and self.string_worker.isRunning():
            self.error("A strings search is already running")
            return
        self.strings_table.set_rows([])
        self.strings_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.statusBar().showMessage(f"Searching memory strings for {keyword!r}")
        self.string_worker = StringScanner(
            self.image, keyword, self.strings_minimum.value(), self.strings_case.isChecked(),
            self.strings_ascii.isChecked(), self.strings_utf16.isChecked(), self.strings_limit.value(), self)
        self.string_worker.ready.connect(self.strings_finished)
        self.string_worker.finished.connect(lambda: self.strings_button.setEnabled(True))
        self.string_worker.start()

    def strings_finished(self, rows, error, truncated):
        self.strings_table.set_rows(rows)
        self.cancel_button.setEnabled(bool(self.runner.active))
        if error:
            self.log.appendPlainText("Strings search: " + error)
            self.statusBar().showMessage(error)
        else:
            suffix = " (result limit reached)" if truncated else ""
            message = f"Strings search complete: {len(rows):,} matches{suffix}"
            self.log.appendPlainText(message)
            self.statusBar().showMessage(message)

    def closeEvent(self, event):
        if self.runner.active or any(thread.isRunning() for thread in self.findChildren(QThread)):
            self.runner.cancel()
            if self.string_worker:
                self.string_worker.cancel()
            if self.hash_worker:
                self.hash_worker.requestInterruption()
            self.statusBar().showMessage("Cancelling work. Close again when it finishes.")
            event.ignore()
            return
        if self.case:
            self.case.close()
        event.accept()


def main():
    parser = argparse.ArgumentParser(description="VolScope native memory investigation workspace")
    parser.add_argument("--demo", action="store_true", help="Open synthetic training evidence")
    args = parser.parse_args()
    app = QApplication(sys.argv[:1])
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    window = MainWindow(demo=args.demo)
    window.show()
    sys.exit(app.exec())
