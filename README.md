# Repoglance

Repoglance is a local Git repository health and cleanup dashboard.

This repository uses separate source folders for platform-specific app builds.
The first implemented source folder is the macOS app:

```text
repoglance/
├── mac_src/
├── mac_export/
├── windows_src/
├── windows_export/
├── linux_src/
└── linux_export/
```

Only `mac_src/` exists for now. Windows and Linux source folders can be created
from the same app structure when those builds are needed.

Repoglance scans local Git repositories, stores scan history in its own SQLite
database, and highlights cleanup and security issues that may deserve attention.

Some actions are intentionally destructive: Repoglance can delete working-tree
paths, rewrite Git history for selected paths, run Git garbage collection, and
force-push rewritten branches/tags when you explicitly choose those actions.
Use those actions only on repositories you have backed up and understand.

## macOS Source

```bash
cd mac_src
npm install
npm run tauri dev
```

For checks:

```bash
npm run build
cargo check --workspace
```
