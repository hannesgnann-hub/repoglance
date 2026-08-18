use std::{
    collections::HashSet,
    fs,
    path::Component,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

use repoglance_core::{
    scan_repository_path_with_options, IgnoredFinding, RepositoryDetails, RepositoryOverview,
    ScanOptions, Storage,
};
use tauri::{image::Image, Manager, State};

struct AppState {
    storage: Mutex<Storage>,
    cancelled_scans: Mutex<HashSet<i64>>,
}

#[tauri::command]
async fn add_repository(path: String, state: State<'_, AppState>) -> Result<RepositoryOverview, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.add_repository(Path::new(&path)).map_err(to_message)
}

#[tauri::command]
async fn remove_repository(id: i64, state: State<'_, AppState>) -> Result<(), String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.remove_repository(id).map_err(to_message)
}

#[tauri::command]
async fn set_favorite(
    id: i64,
    favorite: bool,
    state: State<'_, AppState>,
) -> Result<Vec<RepositoryOverview>, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.set_favorite(id, favorite).map_err(to_message)?;
    storage.repositories().map_err(to_message)
}

#[tauri::command]
async fn list_repositories(state: State<'_, AppState>) -> Result<Vec<RepositoryOverview>, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.repositories().map_err(to_message)
}

#[tauri::command]
async fn get_repository_details(
    id: i64,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.details(id).map_err(to_message)
}

#[tauri::command]
async fn scan_repository(
    id: i64,
    deep_history: Option<bool>,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    scan_and_save(id, deep_history.unwrap_or(false), &state)
}

#[tauri::command]
async fn cancel_scan(id: i64, state: State<'_, AppState>) -> Result<(), String> {
    let mut cancelled = state
        .cancelled_scans
        .lock()
        .map_err(|err| err.to_string())?;
    cancelled.insert(id);
    Ok(())
}

#[tauri::command]
async fn apply_gitignore_entries(
    repository_id: i64,
    entries: Vec<String>,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repository = storage.repository(repository_id).map_err(to_message)?;
    drop(storage);

    let repository_root = Path::new(&repository.path)
        .canonicalize()
        .map_err(|err| format!("Repository path could not be resolved: {err}"))?;
    add_gitignore_entries(&repository_root, &entries)?;

    scan_and_save(repository_id, false, &state)
}

/// Appends any of `entries` that aren't already present (as a whole,
/// trimmed line) to the repository's `.gitignore`, creating it if needed.
fn add_gitignore_entries(repository_root: &Path, entries: &[String]) -> Result<(), String> {
    let gitignore_path = repository_root.join(".gitignore");
    let existing = fs::read_to_string(&gitignore_path).unwrap_or_default();
    let mut next = existing.clone();
    let mut changed = false;

    if !next.is_empty() && !next.ends_with('\n') {
        next.push('\n');
    }

    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() || entry.contains('\n') || entry.contains('\r') {
            continue;
        }
        if !existing.lines().any(|line| line.trim() == entry) {
            next.push_str(entry);
            next.push('\n');
            changed = true;
        }
    }

    if changed {
        fs::write(&gitignore_path, next)
            .map_err(|err| format!("{} could not be updated: {err}", gitignore_path.display()))?;
    }

    Ok(())
}

/// Marks each `(category, path)` pair from `paths` as ignored under
/// `category` for this repository, then rescans so the change is reflected
/// immediately.
#[tauri::command]
async fn ignore_findings(
    repository_id: i64,
    category: String,
    paths: Vec<String>,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let entries: Vec<(String, String)> = paths.into_iter().map(|path| (category.clone(), path)).collect();
    storage.ignore_findings(repository_id, &entries).map_err(to_message)?;
    drop(storage);

    scan_and_save(repository_id, false, &state)
}

#[tauri::command]
async fn list_ignored_findings(
    repository_id: i64,
    state: State<'_, AppState>,
) -> Result<Vec<IgnoredFinding>, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.ignored_findings(repository_id).map_err(to_message)
}

#[tauri::command]
async fn unignore_finding(
    id: i64,
    repository_id: i64,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.unignore_finding(id).map_err(to_message)?;
    drop(storage);

    scan_and_save(repository_id, false, &state)
}

fn scan_and_save(
    id: i64,
    deep_history: bool,
    state: &State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    {
        let mut cancelled = state
            .cancelled_scans
            .lock()
            .map_err(|err| err.to_string())?;
        cancelled.remove(&id);
    }

    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repository = storage.repository(id).map_err(to_message)?;
    let ignored = storage.ignored_findings_set(id).map_err(to_message)?;
    drop(storage);

    let is_cancelled = || {
        state
            .cancelled_scans
            .lock()
            .map(|cancelled| cancelled.contains(&id))
            .unwrap_or(true)
    };
    let scan = scan_repository_path_with_options(
        id,
        Path::new(&repository.path),
        ScanOptions { deep_history },
        &ignored,
        &is_cancelled,
    )
    .map_err(to_message)?;
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.save_scan(scan).map_err(to_message)
}

#[tauri::command]
async fn scan_all_repositories(state: State<'_, AppState>) -> Result<Vec<RepositoryOverview>, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repositories = storage.repositories().map_err(to_message)?;

    for repository in repositories
        .into_iter()
        .filter(|repository| !repository.missing)
    {
        let ignored = storage.ignored_findings_set(repository.id).unwrap_or_default();
        if let Ok(scan) = scan_repository_path_with_options(
            repository.id,
            Path::new(&repository.path),
            ScanOptions::quick(),
            &ignored,
            &|| false,
        ) {
            let _ = storage.save_scan(scan);
        }
    }

    storage.repositories().map_err(to_message)
}

#[tauri::command]
async fn delete_repository_paths(
    repository_id: i64,
    relative_paths: Vec<String>,
    gitignore_entries: Vec<String>,
    bytes_freed: u64,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    if relative_paths.is_empty() {
        return Err("No paths were selected.".into());
    }

    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repository = storage.repository(repository_id).map_err(to_message)?;
    let repository_root = Path::new(&repository.path)
        .canonicalize()
        .map_err(|err| format!("Repository path could not be resolved: {err}"))?;

    for relative_path in &relative_paths {
        let target = resolve_deletable_path(&repository_root, relative_path)?;
        let metadata = fs::symlink_metadata(&target)
            .map_err(|err| format!("{} could not be inspected: {err}", target.display()))?;

        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(&target)
                .map_err(|err| format!("{} could not be deleted: {err}", target.display()))?;
        } else {
            fs::remove_file(&target)
                .map_err(|err| format!("{} could not be deleted: {err}", target.display()))?;
        }
    }

    if !gitignore_entries.is_empty() {
        add_gitignore_entries(&repository_root, &gitignore_entries)?;
    }

    let _ = storage.log_cleanup_event(
        repository_id,
        &repository.name,
        "working_tree",
        relative_paths.len() as i64,
        bytes_freed,
    );

    let ignored = storage.ignored_findings_set(repository_id).map_err(to_message)?;
    let scan = scan_repository_path_with_options(
        repository_id,
        &repository_root,
        ScanOptions::quick(),
        &ignored,
        &|| false,
    )
    .map_err(to_message)?;
    storage.save_scan(scan).map_err(to_message)
}

#[tauri::command]
async fn delete_paths_from_git_history(
    repository_id: i64,
    relative_paths: Vec<String>,
    confirmation: String,
    gitignore_entries: Vec<String>,
    bytes_freed: u64,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    if confirmation != "REWRITE HISTORY" {
        return Err("History rewrite confirmation did not match.".into());
    }
    if relative_paths.is_empty() {
        return Err("No paths were selected.".into());
    }

    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repository = storage.repository(repository_id).map_err(to_message)?;
    drop(storage);

    let repository_root = Path::new(&repository.path)
        .canonicalize()
        .map_err(|err| format!("Repository path could not be resolved: {err}"))?;
    for relative_path in &relative_paths {
        validate_relative_git_path(relative_path)?;
    }
    ensure_clean_worktree(&repository_root)?;

    rewrite_history_remove_paths(&repository_root, &relative_paths)?;
    for relative_path in &relative_paths {
        delete_existing_repository_path(&repository_root, relative_path)?;
    }

    if !gitignore_entries.is_empty() {
        add_gitignore_entries(&repository_root, &gitignore_entries)?;
    }

    {
        let storage = state.storage.lock().map_err(|err| err.to_string())?;
        let _ = storage.log_cleanup_event(
            repository_id,
            &repository.name,
            "git_history",
            relative_paths.len() as i64,
            bytes_freed,
        );
    }

    scan_and_save(repository_id, false, &state)
}

#[tauri::command]
async fn force_push_repository(repository_id: i64, state: State<'_, AppState>) -> Result<(), String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repository = storage.repository(repository_id).map_err(to_message)?;
    drop(storage);

    let repository_root = Path::new(&repository.path)
        .canonicalize()
        .map_err(|err| format!("Repository path could not be resolved: {err}"))?;

    run_git(&repository_root, &["push", "--force", "--all"])?;
    run_git(&repository_root, &["push", "--force", "--tags"])?;
    Ok(())
}

/// Total bytes freed across every repository via Delete / Delete on Git,
/// for as long as this app installation has been tracking it.
#[tauri::command]
async fn total_bytes_freed(state: State<'_, AppState>) -> Result<u64, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.total_bytes_freed().map_err(to_message)
}

/// Shows which refs a force push would actually change, using Git's own
/// `--dry-run --porcelain` push (no history is touched) so the user sees
/// what they are about to overwrite before confirming a destructive push.
#[tauri::command]
async fn preview_force_push(repository_id: i64, state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repository = storage.repository(repository_id).map_err(to_message)?;
    drop(storage);

    let repository_root = Path::new(&repository.path)
        .canonicalize()
        .map_err(|err| format!("Repository path could not be resolved: {err}"))?;

    let mut lines = Vec::new();
    lines.extend(dry_run_force_push_lines(&repository_root, "--all")?);
    lines.extend(dry_run_force_push_lines(&repository_root, "--tags")?);
    Ok(lines)
}

fn dry_run_force_push_lines(repository_root: &Path, scope: &str) -> Result<Vec<String>, String> {
    let output = run_git_capture(
        repository_root,
        &["push", "--force", "--dry-run", "--porcelain", scope],
    )?;
    Ok(parse_push_porcelain(&output))
}

/// Turns `git push --porcelain` ref lines (`<flag>\t<from>:<to>\t<summary>`)
/// into short human-readable descriptions, dropping the header/footer lines
/// and refs that would not actually change.
fn parse_push_porcelain(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|raw_line| {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with("To ") || line == "Done" {
                return None;
            }

            let mut columns = line.splitn(3, '\t');
            let flag = columns.next().unwrap_or("").trim();
            let refs = columns.next().unwrap_or("").trim();
            let summary = columns.next().unwrap_or("").trim();
            if refs.is_empty() {
                return None;
            }

            let description = match flag {
                "=" => return None,
                "+" => "will be force-updated",
                "*" => "will be created",
                "-" => "will be deleted",
                "!" => "rejected",
                _ => "will be updated",
            };
            let suffix = if summary.is_empty() {
                String::new()
            } else {
                format!(" ({summary})")
            };
            Some(format!("{refs} — {description}{suffix}"))
        })
        .collect()
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let db_path = database_path(app)?;
            let storage = Storage::new(db_path).map_err(|err| anyhow::anyhow!(err.to_string()))?;
            app.manage(AppState {
                storage: Mutex::new(storage),
                cancelled_scans: Mutex::new(HashSet::new()),
            });
            if let Some(window) = app.get_webview_window("main") {
                let icon = Image::new(include_bytes!("../icons/icon_128.rgba"), 128, 128);
                let _ = window.set_icon(icon);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            add_repository,
            remove_repository,
            set_favorite,
            list_repositories,
            scan_repository,
            scan_all_repositories,
            get_repository_details,
            delete_repository_paths,
            delete_paths_from_git_history,
            force_push_repository,
            preview_force_push,
            total_bytes_freed,
            apply_gitignore_entries,
            ignore_findings,
            list_ignored_findings,
            unignore_finding,
            cancel_scan
        ])
        .run(tauri::generate_context!())
        .expect("error while running Repoglance");
}

fn database_path(app: &tauri::App) -> tauri::Result<PathBuf> {
    let base = app.path().app_data_dir().or_else(|_| {
        dirs::data_local_dir()
            .map(|dir| dir.join("Repoglance"))
            .ok_or_else(|| tauri::Error::AssetNotFound("app data directory".into()))
    })?;
    std::fs::create_dir_all(&base)?;
    Ok(base.join("repoglance.sqlite3"))
}

fn to_message(error: anyhow::Error) -> String {
    error.to_string()
}

fn resolve_deletable_path(repository_root: &Path, relative_path: &str) -> Result<PathBuf, String> {
    validate_relative_git_path(relative_path)?;
    let relative = Path::new(relative_path);
    let target = repository_root.join(relative);
    let canonical_target = target
        .canonicalize()
        .map_err(|err| format!("{} could not be resolved: {err}", target.display()))?;
    if !canonical_target.starts_with(repository_root) {
        return Err("Resolved path is outside the repository.".into());
    }

    Ok(canonical_target)
}

fn delete_existing_repository_path(
    repository_root: &Path,
    relative_path: &str,
) -> Result<(), String> {
    let target = repository_root.join(Path::new(relative_path));
    if !target.exists() && fs::symlink_metadata(&target).is_err() {
        return Ok(());
    }

    let target = resolve_deletable_path(repository_root, relative_path)?;
    let metadata = fs::symlink_metadata(&target)
        .map_err(|err| format!("{} could not be inspected: {err}", target.display()))?;

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(&target)
            .map_err(|err| format!("{} could not be deleted: {err}", target.display()))?;
    } else {
        fs::remove_file(&target)
            .map_err(|err| format!("{} could not be deleted: {err}", target.display()))?;
    }

    Ok(())
}

fn validate_relative_git_path(relative_path: &str) -> Result<(), String> {
    let relative = Path::new(relative_path);
    if relative_path.trim().is_empty() || relative.is_absolute() {
        return Err("Only repository-relative paths are allowed.".into());
    }

    for component in relative.components() {
        match component {
            Component::Normal(value) if value == ".git" => {
                return Err("Repoglance will not delete anything inside .git.".into());
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("Path traversal is not allowed.".into());
            }
            _ => {}
        }
    }

    Ok(())
}

fn ensure_clean_worktree(repository_root: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .current_dir(repository_root)
        .args(["status", "--porcelain"])
        .output()
        .map_err(|err| format!("Could not inspect Git status: {err}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    if !output.stdout.is_empty() {
        return Err(
            "History rewrite requires a clean worktree. Commit or stash your changes first.".into(),
        );
    }
    Ok(())
}

/// Returns true if `git-filter-repo` is installed and usable. It is the tool
/// upstream Git recommends over `filter-branch` (faster, far less prone to
/// leaving stray refs or partially-rewritten history around), so it is
/// preferred whenever it is available.
fn history_rewrite_tool_available() -> bool {
    Command::new("git")
        .args(["filter-repo", "--version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn rewrite_history_remove_paths(repository_root: &Path, relative_paths: &[String]) -> Result<(), String> {
    if history_rewrite_tool_available() {
        rewrite_history_with_filter_repo(repository_root, relative_paths)
    } else {
        rewrite_history_with_filter_branch(repository_root, relative_paths)
    }
}

fn rewrite_history_with_filter_repo(
    repository_root: &Path,
    relative_paths: &[String],
) -> Result<(), String> {
    let origin_url = run_git_capture(repository_root, &["remote", "get-url", "origin"])
        .ok()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty());

    // A single filter-repo run over all paths is both correct (it rewrites
    // history once) and far cheaper than running it once per path, which
    // would re-walk and rewrite the *entire* history N times.
    let mut args: Vec<&str> = vec!["filter-repo", "--force", "--invert-paths"];
    for path in relative_paths {
        args.push("--path");
        args.push(path);
    }
    run_git(repository_root, &args)?;

    // git-filter-repo removes the `origin` remote by default as a guard
    // against accidentally pushing rewritten history back to where it came
    // from. Repoglance's flow is an explicit, user-confirmed rewrite followed
    // by an explicit force push, so restore it if it was there before.
    if let Some(url) = origin_url {
        let remotes = run_git_capture(repository_root, &["remote"]).unwrap_or_default();
        let has_origin = remotes.lines().any(|line| line.trim() == "origin");
        if !has_origin {
            run_git(repository_root, &["remote", "add", "origin", &url])?;
        }
    }

    Ok(())
}

fn rewrite_history_with_filter_branch(
    repository_root: &Path,
    relative_paths: &[String],
) -> Result<(), String> {
    let quoted_paths = relative_paths
        .iter()
        .map(|path| shell_quote(path))
        .collect::<Vec<_>>()
        .join(" ");
    let index_filter = format!("git rm -r --cached --ignore-unmatch -- {quoted_paths}");
    run_git(
        repository_root,
        &[
            "filter-branch",
            "--force",
            "--index-filter",
            &index_filter,
            "--prune-empty",
            "--tag-name-filter",
            "cat",
            "--",
            "--all",
        ],
    )?;

    cleanup_rewritten_refs(repository_root)?;
    run_git(
        repository_root,
        &["reflog", "expire", "--expire=now", "--all"],
    )?;
    run_git(repository_root, &["gc", "--prune=now", "--aggressive"])?;
    Ok(())
}

fn cleanup_rewritten_refs(repository_root: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .current_dir(repository_root)
        .args(["for-each-ref", "--format=%(refname)", "refs/original"])
        .output()
        .map_err(|err| format!("Could not inspect rewritten refs: {err}"))?;
    if !output.status.success() {
        return Ok(());
    }

    for reference in String::from_utf8_lossy(&output.stdout).lines() {
        if !reference.trim().is_empty() {
            run_git(repository_root, &["update-ref", "-d", reference.trim()])?;
        }
    }
    Ok(())
}

fn run_git(repository_root: &Path, args: &[&str]) -> Result<(), String> {
    run_git_capture(repository_root, args).map(|_| ())
}

fn run_git_capture(repository_root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(repository_root)
        .env("FILTER_BRANCH_SQUELCH_WARNING", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .output()
        .map_err(|err| format!("Could not run git {}: {err}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(if stderr.is_empty() { stdout } else { stderr });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "repoglance_main_test_{name}_{}_{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> PathBuf {
            self.0.canonicalize().unwrap()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn validate_relative_git_path_rejects_empty_and_absolute() {
        assert!(validate_relative_git_path("").is_err());
        assert!(validate_relative_git_path("   ").is_err());
        assert!(validate_relative_git_path("/etc/passwd").is_err());
    }

    #[test]
    fn validate_relative_git_path_rejects_parent_dir_traversal() {
        assert!(validate_relative_git_path("../outside").is_err());
        assert!(validate_relative_git_path("nested/../../outside").is_err());
    }

    #[test]
    fn validate_relative_git_path_rejects_dot_git_component() {
        assert!(validate_relative_git_path(".git/config").is_err());
        assert!(validate_relative_git_path("sub/.git/hooks/pre-commit").is_err());
    }

    #[test]
    fn validate_relative_git_path_accepts_normal_relative_paths() {
        assert!(validate_relative_git_path("src/main.rs").is_ok());
        assert!(validate_relative_git_path("large-file.bin").is_ok());
    }

    #[test]
    fn resolve_deletable_path_accepts_file_inside_repository() {
        let repo = TempDir::new("inside");
        fs::write(repo.0.join("keep.txt"), b"data").unwrap();

        let resolved = resolve_deletable_path(&repo.path(), "keep.txt").unwrap();
        assert_eq!(resolved, repo.path().join("keep.txt"));
    }

    #[test]
    fn resolve_deletable_path_rejects_traversal_before_touching_disk() {
        let repo = TempDir::new("traversal");
        let err = resolve_deletable_path(&repo.path(), "../secret.txt").unwrap_err();
        assert!(err.contains("traversal"));
    }

    #[test]
    fn parse_push_porcelain_describes_changed_refs_and_drops_noise() {
        let output = "To git@example.com:acme/repo.git\n\
+\trefs/heads/main:refs/heads/main\tforced update\n\
=\trefs/heads/stable:refs/heads/stable\t[up to date]\n\
*\trefs/tags/v1:refs/tags/v1\t[new tag]\n\
Done\n";

        let lines = parse_push_porcelain(output);

        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("refs/heads/main:refs/heads/main"));
        assert!(lines[0].contains("force-updated"));
        assert!(lines[1].contains("refs/tags/v1:refs/tags/v1"));
        assert!(lines[1].contains("will be created"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_deletable_path_rejects_symlink_escaping_repository() {
        use std::os::unix::fs::symlink;

        let repo = TempDir::new("symlink-repo");
        let outside = TempDir::new("symlink-outside");
        fs::write(outside.0.join("target.txt"), b"secret").unwrap();
        symlink(outside.path().join("target.txt"), repo.0.join("escape")).unwrap();

        let err = resolve_deletable_path(&repo.path(), "escape").unwrap_err();
        assert!(err.contains("outside the repository"));
    }
}
