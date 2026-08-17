use std::{
    collections::HashSet,
    fs,
    path::Component,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};

use repoglance_core::{
    scan_repository_path_with_options, RepositoryDetails, RepositoryOverview, ScanOptions, Storage,
};
use tauri::{image::Image, Manager, State};

struct AppState {
    storage: Mutex<Storage>,
    cancelled_scans: Mutex<HashSet<i64>>,
}

#[tauri::command]
fn add_repository(path: String, state: State<'_, AppState>) -> Result<RepositoryOverview, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.add_repository(Path::new(&path)).map_err(to_message)
}

#[tauri::command]
fn remove_repository(id: i64, state: State<'_, AppState>) -> Result<(), String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.remove_repository(id).map_err(to_message)
}

#[tauri::command]
fn list_repositories(state: State<'_, AppState>) -> Result<Vec<RepositoryOverview>, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.repositories().map_err(to_message)
}

#[tauri::command]
fn get_repository_details(
    id: i64,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.details(id).map_err(to_message)
}

#[tauri::command]
fn scan_repository(
    id: i64,
    deep_history: Option<bool>,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    scan_and_save(id, deep_history.unwrap_or(false), &state)
}

#[tauri::command]
fn cancel_scan(id: i64, state: State<'_, AppState>) -> Result<(), String> {
    let mut cancelled = state
        .cancelled_scans
        .lock()
        .map_err(|err| err.to_string())?;
    cancelled.insert(id);
    Ok(())
}

#[tauri::command]
fn apply_gitignore_entries(
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
        &is_cancelled,
    )
    .map_err(to_message)?;
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    storage.save_scan(scan).map_err(to_message)
}

#[tauri::command]
fn scan_all_repositories(state: State<'_, AppState>) -> Result<Vec<RepositoryOverview>, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repositories = storage.repositories().map_err(to_message)?;

    for repository in repositories
        .into_iter()
        .filter(|repository| !repository.missing)
    {
        if let Ok(scan) = scan_repository_path_with_options(
            repository.id,
            Path::new(&repository.path),
            ScanOptions::quick(),
            &|| false,
        ) {
            let _ = storage.save_scan(scan);
        }
    }

    storage.repositories().map_err(to_message)
}

#[tauri::command]
fn delete_repository_path(
    repository_id: i64,
    relative_path: String,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repository = storage.repository(repository_id).map_err(to_message)?;
    let repository_root = Path::new(&repository.path)
        .canonicalize()
        .map_err(|err| format!("Repository path could not be resolved: {err}"))?;
    let target = resolve_deletable_path(&repository_root, &relative_path)?;

    let metadata = fs::symlink_metadata(&target)
        .map_err(|err| format!("{} could not be inspected: {err}", target.display()))?;

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(&target)
            .map_err(|err| format!("{} could not be deleted: {err}", target.display()))?;
    } else {
        fs::remove_file(&target)
            .map_err(|err| format!("{} could not be deleted: {err}", target.display()))?;
    }

    let scan = scan_repository_path_with_options(
        repository_id,
        &repository_root,
        ScanOptions::quick(),
        &|| false,
    )
    .map_err(to_message)?;
    storage.save_scan(scan).map_err(to_message)
}

#[tauri::command]
fn delete_path_from_git_history(
    repository_id: i64,
    relative_path: String,
    confirmation: String,
    state: State<'_, AppState>,
) -> Result<RepositoryDetails, String> {
    if confirmation != "REWRITE HISTORY" {
        return Err("History rewrite confirmation did not match.".into());
    }

    let storage = state.storage.lock().map_err(|err| err.to_string())?;
    let repository = storage.repository(repository_id).map_err(to_message)?;
    drop(storage);

    let repository_root = Path::new(&repository.path)
        .canonicalize()
        .map_err(|err| format!("Repository path could not be resolved: {err}"))?;
    validate_relative_git_path(&relative_path)?;
    ensure_clean_worktree(&repository_root)?;

    let quoted_path = shell_quote(&relative_path);
    let index_filter = format!("git rm -r --cached --ignore-unmatch -- {quoted_path}");
    run_git(
        &repository_root,
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

    cleanup_rewritten_refs(&repository_root)?;
    run_git(
        &repository_root,
        &["reflog", "expire", "--expire=now", "--all"],
    )?;
    run_git(&repository_root, &["gc", "--prune=now", "--aggressive"])?;
    delete_existing_repository_path(&repository_root, &relative_path)?;

    scan_and_save(repository_id, false, &state)
}

#[tauri::command]
fn force_push_repository(repository_id: i64, state: State<'_, AppState>) -> Result<(), String> {
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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
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
            list_repositories,
            scan_repository,
            scan_all_repositories,
            get_repository_details,
            delete_repository_path,
            delete_path_from_git_history,
            force_push_repository,
            apply_gitignore_entries,
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
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
