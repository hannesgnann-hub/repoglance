# Repoglance for Windows

Repoglance is a local Git repository health and cleanup dashboard built as a
Tauri desktop app.

The app can inspect local Git repositories, persist scan metadata in its own
SQLite database, and show issues that may deserve attention.

Some actions are intentionally destructive: Repoglance can delete working-tree
paths, rewrite Git history for selected paths, run Git garbage collection, and
force-push rewritten branches/tags when you explicitly choose those actions.
Use those actions only on repositories you have backed up and understand.

This source tree targets Windows specifically. It has no platform-specific
application logic of its own (unlike, say, a shell-alias manager) - Repoglance's
core scanning logic works the same way on every OS via the `git` CLI, and the
one platform-conditional code path (`repoglance-core`'s directory-size helper)
already falls back to a plain directory walk wherever the Unix `du` command
isn't available, which covers Windows automatically.

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

## Build Windows App

```bash
npm run tauri build
```

This produces an NSIS installer (`.exe`). Build it on a Windows machine (or a
Windows CI runner) - Tauri does not support cross-compiling its bundler output
from macOS/Linux.
