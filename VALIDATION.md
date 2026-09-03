# Validation record

Validated on Windows with Python 3.12, PySide6 6.11.2, and Volatility 3.28.0.

- All 10 automated tests passed: core normalization/correlation/case tests and headless Qt integration tests.
- Background subprocess tests verified UI event processing during execution, successful JSON ingestion, nonzero exits, malformed output, and cancellation clearing the queue.
- The synthetic demo opened all eight sections and showed correlated process metadata, network rows, and DLL rows.
- Streaming SHA1/SHA256 results matched known digests.
- Installed Volatility CLI help verified the fully qualified pstree, pslist, dlllist, dumpfiles, and vadinfo plugins and their relevant argument contracts.
- The demo was rendered offscreen and visually inspected. See `preview.png`.

Not yet validated: real memory-image analysis or artifact recovery, live Linux desktop behavior, large-image performance, or Linux/macOS memory-image support. No memory capture was supplied. Tests do not establish forensic completeness or accuracy of the underlying Volatility plugins.
