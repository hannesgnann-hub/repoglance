# Repoglance for Linux

Repoglance is a local Git repository health and cleanup dashboard built as a
Tauri desktop app.

The app can inspect local Git repositories, persist scan metadata in its own
SQLite database, and show issues that may deserve attention.

Some actions are intentionally destructive: Repoglance can delete working-tree
paths, rewrite Git history for selected paths, run Git garbage collection, and
force-push rewritten branches/tags when you explicitly choose those actions.
Use those actions only on repositories you have backed up and understand.

This source tree targets Linux specifically. It has no platform-specific
application logic of its own (unlike, say, a shell-alias manager) - Repoglance's
core scanning logic works the same way on every OS via the `git` CLI, and the
one platform-conditional code path (`repoglance-core`'s directory-size helper)
uses the Unix `du` command directly, which Linux has natively.

## Development

```bash
npm install
npm run tauri dev
```

Building the Tauri bundler targets (`deb`/`rpm`/`appimage`) additionally needs
the usual Tauri Linux system dependencies (WebKitGTK, etc.) - see the
[Tauri Linux prerequisites](https://tauri.app/start/prerequisites/) for your
distribution.

## Checks

```bash
npm run build
cargo check --workspace
```

## Build Linux App

```bash
npm run tauri build
```

This produces a `.deb`, `.rpm`, and an AppImage. Build it on Linux (or a Linux
CI runner) - Tauri does not support cross-compiling its bundler output from
macOS/Windows.
