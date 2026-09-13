# Validation record

Validated on Windows with Python 3.12, PySide6 6.11.2, and Volatility 3.28.0.

- The automated suite covers core normalization/correlation/case behavior and headless Qt integration.
- Background subprocess tests verified UI event processing during execution, successful JSON ingestion, nonzero exits, malformed output, and cancellation clearing the queue.
- The synthetic demo opened all nine sections and showed correlated process metadata, network rows, and DLL rows.
- Streaming SHA1/SHA256 results matched known digests.
- Installed Volatility CLI help verified the Windows and Linux plugin contracts, including Linux `banners`, `pslist`, `pstree`, `psaux`, `sockstat`, `elfs`, `lsof`, and `proc.Maps`.
- The demo was rendered offscreen and visually inspected. See `preview.png`.
- The strings scanner has coverage for literal, case-insensitive ASCII and UTF-16LE matching when GNU `strings` is installed; environments without it exercise the dependency error path.

Not yet validated: real Linux or Windows memory-image analysis or artifact recovery, live Linux desktop behavior, large-image performance, or macOS desktop behavior. No memory capture was supplied. Tests do not establish forensic completeness or accuracy of the underlying Volatility plugins.
