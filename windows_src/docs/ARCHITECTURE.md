# Repoglance Windows Architecture

`windows_src` is the Windows source tree for the local Repoglance desktop app.

## Layout

```text
windows_src/
├── crates/
│   ├── repoglance-core/   # scanning, scoring, SQLite storage (pure Rust, no Tauri)
│   └── repoglance-cli/    # thin debug CLI wrapper around repoglance-core
├── src/                   # React + TypeScript frontend
├── src-tauri/             # Tauri shell: commands, window, capabilities
├── docs/
└── package.json
```

## Runtime Shape

- React + TypeScript renders the desktop UI and calls Tauri commands via
  `@tauri-apps/api`'s `invoke()`.
- `src-tauri/src/main.rs` hosts the application window, exposes Tauri
  commands, and holds an `AppState` (the SQLite `Storage` handle plus
  in-flight scan cancellation flags) behind a `Mutex`.
- `repoglance-core` owns the actual scanning, scoring, and SQLite persistence
  logic; `main.rs` only orchestrates it and enforces path-safety checks
  before touching the filesystem or Git.
- The local database lives at the OS app-data directory (e.g.
  `%APPDATA%\dev.hannesgnann.repoglance\repoglance.sqlite3` on Windows) and is
  created/migrated automatically on first launch.

## Read vs. Write: What the App Actually Does

Scanning itself is always read-only: `repoglance-core::scan_repository_path_with_options`
only runs read-only `git` subcommands and reads files, never mutates a
scanned repository.

Beyond scanning, the app *can* perform destructive actions, but only when the
user explicitly triggers them from a specific issue/finding - nothing runs
automatically:

- **Delete** - removes a working-tree path (file or directory). No Git
  history is touched.
- **Delete on Git** - rewrites the entire local Git history to strip one or
  more paths (`git filter-repo` if installed, otherwise a `git filter-branch`
  fallback), then removes the path from the working tree. Requires a clean
  worktree and a typed confirmation. This never touches the remote by itself.
- **Force Push** - the only command that touches a remote; pushes the
  rewritten local history, overwriting whatever is on `origin`. A dry-run
  preview (`git push --dry-run --porcelain`) is fetched first so the user
  sees which refs would change before confirming.
- **Ignore** - not destructive at all; marks a `(category, path)` pair as
  dismissed for a repository so it's excluded from future scans and the
  score, without touching the repository on disk.

## Local Tracking (SQLite)

Beyond the per-scan `scans`/`issues`/`issue_paths` tables, the database keeps
a few small, repository-independent logs:

- `ignored_findings` - dismissed findings, applied as a filter during
  scanning (see `filter_ignored_findings` in `repoglance-core`).
- `cleanup_events` - a running log of bytes actually freed by Delete /
  Delete on Git, used for the "freed so far" figure on the dashboard. Not
  tied to `repositories` by foreign key on purpose, so it keeps counting
  even after a repository is removed from tracking.
- `repositories.favorite` - lets a repository be pinned to the top of the
  dashboard list.

## Cross-Platform Notes

The only platform-conditional code in the whole app is
`repoglance-core::scanner::fast_directory_size`, which shells out to `du -sk`
on Unix (`#[cfg(unix)]`) and falls back to a plain recursive directory walk
everywhere else - on Windows, that fallback path is always the one used.
Every other part of the app - the scanner's `git`
subprocess calls, the SQLite storage layer, the React frontend - is
identical across the `mac_src`, `windows_src`, and `linux_src` source trees;
only Tauri's bundler config (icons, installer target) differs per platform.
