# Repoglance macOS Architecture

`mac_src` is the macOS source tree for the local Repoglance desktop app.

## Layout

```text
mac_src/
├── crates/
│   ├── repoglance-core/
│   └── repoglance-cli/
├── src/
├── src-tauri/
├── docs/
└── package.json
```

## Runtime Shape

- React + TypeScript renders the desktop UI.
- Tauri hosts the local application window and exposes commands.
- `repoglance-core` owns scanning, scoring, issue creation, and SQLite storage.
- The app is read-only toward scanned repositories.

## Read-Only Scanner Rule

Repoglance may run read-only Git commands and read files. It must not delete,
rewrite, reset, clean, or otherwise mutate a scanned repository in version 0.1.
