# Repoglance for macOS

Repoglance is a local Git repository health and cleanup dashboard built as a
Tauri desktop app.

The app can inspect local Git repositories, persist scan metadata in its own
SQLite database, and show issues that may deserve attention.

Some actions are intentionally destructive: Repoglance can delete working-tree
paths, rewrite Git history for selected paths, run Git garbage collection, and
force-push rewritten branches/tags when you explicitly choose those actions.
Use those actions only on repositories you have backed up and understand.

## Development

```bash
npm install
npm run tauri dev
```

## Checks

```bash
npm run build
cargo check --workspace
```

## Build macOS App

```bash
npm run tauri build
```
