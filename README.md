# Repoglance

Repoglance is a local Git repository health and cleanup dashboard.

Repoglance scans local Git repositories, stores scan history in its own SQLite
database, and highlights cleanup and security issues that may deserve attention.

Some actions are intentionally destructive: Repoglance can delete working-tree
paths, rewrite Git history for selected paths, run Git garbage collection, and
force-push rewritten branches/tags when you explicitly choose those actions.
Use those actions only on repositories you have backed up and understand.

## Folder Structure

This repository uses separate, fully independent source folders per platform
- each one is its own standalone Tauri project (own `package.json`,
`src-tauri/`, `crates/`) rather than a shared monorepo. There is no
platform-specific *application logic* to speak of (Repoglance's scanning
works identically everywhere via the `git` CLI), so the three trees are
near-identical; only Tauri's bundler config (icons, installer target) differs.
See each platform's own `docs/ARCHITECTURE.md` for details.

```text
repoglance/
├── mac_src/       # macOS source tree (.app / .dmg)
├── mac_export/
├── windows_src/   # Windows source tree (NSIS .exe installer)
├── windows_export/
├── linux_src/     # Linux source tree (.deb / .rpm / AppImage)
└── linux_export/
```

App Store / sandboxed variants (as some other local apps have under
`*_app_store` / `*_store` folders) are intentionally not set up here - this
app doesn't need that distribution path. The `*_export/` folders are where
built installers/bundles land; they aren't wired up yet (`npm run tauri
build` still works per platform - only the export/packaging step around it
is left for later).

## macOS Source

```bash
cd mac_src
npm install
npm run tauri dev
```

## Windows Source

```bash
cd windows_src
npm install
npm run tauri dev
```

## Linux Source

```bash
cd linux_src
npm install
npm run tauri dev
```

Building the Linux bundler targets additionally needs the usual Tauri Linux
system dependencies (WebKitGTK, etc.) - see the
[Tauri Linux prerequisites](https://tauri.app/start/prerequisites/).

## Checks (per platform folder)

```bash
npm run build
cargo check --workspace
```

## Cross-Platform Builds

Tauri does not cross-compile its bundler output. Build (`npm run tauri
build`) each source tree on a machine running that target OS:

| Source folder  | Build on | Bundle target(s)          |
| -------------- | -------- | -------------------------- |
| `mac_src`      | macOS    | `.app`                     |
| `windows_src`  | Windows  | NSIS `.exe`                 |
| `linux_src`    | Linux    | `.deb`, `.rpm`, AppImage    |
