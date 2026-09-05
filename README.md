# VolScope

A native PySide6 desktop workspace for Volatility 3 memory investigations. Select a local memory image, inspect its process tree, and correlate process metadata, command lines, network objects, and DLLs without reading large terminal tables.

**MVP scope:** runs on Kali/Linux first, with portable Python/Qt code for Windows and macOS. The current plugin registry analyzes **Windows memory images**, regardless of the host OS. Linux/macOS *image analysis* requires additional plugin adapters. No memory image is uploaded by this application.

## Setup and launch on Kali/Linux

Requires Python 3.10+ and a graphical desktop.

```sh
sudo apt update
sudo apt install python3-venv libegl1 libgl1 libxkbcommon-x11-0 libxcb-cursor0 binutils
cd volscope
chmod +x install-kali.sh
./install-kali.sh
```

The installer detects zsh or bash, creates `.venv`, installs VolScope, creates `~/.local/bin/volscope`, and adds that standard user-bin directory to `.zshrc` or `.bashrc` only when it is missing. It disables a legacy `volscope` alias if one would override the launcher, preserving a backup of the shell configuration. Run `exec "$SHELL"` or open a new terminal, then run `volscope` from anywhere.

Manual setup is also available:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
volscope --demo
# Real investigation:
volscope
```

On Windows, create the environment with `py -m venv .venv`, activate with `.venv\Scripts\Activate.ps1`, then use the same pip and launch commands. On macOS, use the Linux Python environment steps without apt. `python -m volscope` also starts the app.

## Investigation workflow

1. **Open memory image**, then choose a parent directory. A unique case folder containing `case.sqlite` is created, and baseline analysis begins automatically.
2. Baseline runs `windows.info`, `pslist`, `pstree`, `cmdline`, and `netscan` sequentially. Each completed result becomes available even if another plugin fails. Diagnostics appear in the activity panel and are recorded in SQLite.
3. Open **Process Tree**. Expand branches, filter by name/PID, and select a process. The inspector shows metadata/path, command line, and matching network objects. Select rows in Processes or Network to inspect their PID too.
4. Use **Load DLLs for selected PID** to collect its loaded modules. **Memory Regions** uses `vadinfo` for the selected PID. **Files** runs the potentially expensive `filescan` only when requested.
5. **Export process executable (PE)** invokes `pslist --pid PID --dump`. This recovers a process executable when available; it is not a full address-space dump. In Files, select an object and choose **Export selected cached file** to run `dumpfiles --virtaddr OFFSET`. Recovered content may be incomplete or unavailable. Inspect plugin result/status fields; successful plugin execution does not guarantee artifact recovery.
6. **SHA1 / SHA256** streams any selected local file in a background thread. Results appear in the activity panel and can be copied. Hashes are not automatically saved to the case database.
7. **Open case** restores completed evidence. Missing or changed images allow cached review only. Reopen a changed image as a new case. **Run baseline** explicitly refreshes results; cached data is never used to skip a requested run.

Exports go into unique timestamped subdirectories. Files are never executed by the application. Cancel stops the current Volatility subprocess and clears queued work; partial exports may remain. Closing during work cancels it and asks you to close again after completion.

## Interface sections

| Section | Current behavior |
| --- | --- |
| Overview | Image information, counts, workflow |
| Processes | Searchable process metadata table |
| Process Tree | Expandable, searchable parent-child hierarchy and PID inspector |
| Network | Searchable netscan results, PID correlation |
| Files | On-demand file-object scan and cached-file export |
| Memory Regions | On-demand VAD information for selected PID |
| DLLs | On-demand loaded modules for selected PID |
| Timeline | Derived process creation/exit and network creation events |
| Strings Search | Background ASCII/UTF-16LE keyword search of the raw image, with offsets and copying |

## Search memory strings

Open **Strings Search**, enter a literal keyword, choose ASCII and/or UTF-16LE, then click **Search memory**. VolScope runs GNU `strings` directly and performs fixed-text filtering inside the app; it never builds a shell command from your input. This gives the practical behavior of `strings | grep -F keyword` while safely supporting spaces, quotes, and shell characters. Results include the hexadecimal image offset, encoding, and complete matching string. Click a field and press **Ctrl+C** to copy it. The result limit prevents a broad keyword from exhausting memory.

The search scans the raw image, not only a selected process. It can find stale or unrelated data and does not prove which process owned a string.

Tables use Qt models rather than one widget per cell. Filters search all columns. Column widths can be resized. Results and strings are displayed as plain text, not interpreted HTML. The demo is entirely synthetic and uses documentation-only network addresses.

## Copying lab answers

- In any evidence table or the process tree, click a field and press **Ctrl+C** (**Cmd+C** on macOS), or right-click it and choose **Copy value**.
- Copy uses the full value even when the column truncates it. Sorting and filtering preserve the correct value. Missing values copy as empty text.
- In the Metadata, Overview, and activity panels, highlight the desired text and use **Ctrl+C** or the standard right-click **Copy** menu.

## Symbols and troubleshooting

Volatility needs matching symbols. Windows symbols may download automatically on the first run; **Offline symbols** disables online symbol retrieval. Set an optional local symbol directory before running analysis. Symbol setup can take time, with the rest of the GUI still usable. The host must have sufficient RAM for Volatility and the selected result sets.

If analysis fails, inspect the bottom diagnostics panel. Unsatisfied kernel/symbol requirements usually indicate unavailable symbols, an unsupported image, or an incorrect image type. Confirm the same plugin in the installed environment:

```sh
python -m volscope.vol_cli -f /path/to/memory.dmp windows.info.Info
python -m volscope.vol_cli windows.dlllist.DllList --help
```

If Qt reports an xcb platform dependency error on Linux, install the named missing system library. For headless tests only, set `QT_QPA_PLATFORM=offscreen`. For desktop use, a working X11 or Wayland session is required.

## Architecture

```text
src/volscope/
  app.py        Qt workspace, evidence table models, interaction wiring
  core.py       Plugin registry, CLI arguments, JSON normalization, correlation
  runner.py     QProcess queue, cancellation, threaded JSON decode and hashes
  storage.py    Case metadata, normalized results, run audit trail in SQLite
  vol_cli.py    Installed Volatility CLI entry point for subprocess execution
  demo.py       Synthetic training fixture
tests/
  test_core.py  Parser, correlation, tree integrity, arguments, persistence
  test_qt.py    Headless GUI, background jobs, cancellation, streaming hashes
install-kali.sh Detects bash/zsh and installs a global user launcher
```

To add a plugin, register its fully qualified name and PID support in `core.PLUGINS`, then connect a section/action to `run_plugin`. Each run receives separate argv arguments through QProcess (no shell). Add a normalizer if a plugin uses a different schema. PID-scoped results use keys such as `dlllist:4628`. Each case stores image path/size/modification time, normalized JSON, and timestamped run arguments, status, and diagnostics. SQLite operations are on the GUI thread; Volatility execution, JSON decoding, and hashing are background work.

## Validation

```sh
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -v
```

Tests cover nested JSON, missing values, malformed results, orphan/cyclic trees, parent PID reuse, correlation, case round-trips, safe argument boundaries, successful/failed background jobs, cancellation, UI selection, and known hashes. Synthetic fixtures exercise the GUI without a memory image. Real-image end-to-end validation is still required on your target Kali environment; no real memory capture is included in this project.

## Known limits and next steps

- PID-only correlation is approximate, especially for stale network objects and PID reuse. Parent links with clearly newer creation times are detached. The app makes no automatic malware verdicts.
- Data absent from a result is not proof of absence. Baseline errors are visible; a failed refresh leaves the previous successful result available and logs the failure.
- JSON stdout and normalized results are currently held in memory. Very large scans may consume substantial RAM; table refresh and SQLite writes can briefly pause the UI. Streaming ingestion/pagination is a future improvement.
- Timeline is derived from collected rows, not Volatility's comprehensive timeliner. No automatic OS detection, Linux-image plugins, full memory dumping, case annotations, or formal evidence-chain reporting yet.
- Image cache identity uses path, size, and modification time, not a cryptographic fingerprint. Use the hash action for evidence verification. Treat images as immutable during analysis.
- Cases contain sensitive local evidence in an unencrypted SQLite file. Use your normal secured investigation workspace.

Volatility command conventions follow the [official CLI documentation](https://volatility3.readthedocs.io/en/stable/vol-cli.html). Volatility is a separately installed dependency under its own license; this project does not vendor its code.
