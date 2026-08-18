import { invoke } from "@tauri-apps/api/core";
import type { IgnoredFinding, IssueCategory, RepositoryDetails, RepositoryOverview } from "../types";

export function listRepositories() {
  return invoke<RepositoryOverview[]>("list_repositories");
}

export function addRepository(path: string) {
  return invoke<RepositoryOverview>("add_repository", { path });
}

export function removeRepository(id: number) {
  return invoke<void>("remove_repository", { id });
}

export function setFavorite(id: number, favorite: boolean) {
  return invoke<RepositoryOverview[]>("set_favorite", { id, favorite });
}

export function scanRepository(id: number, deepHistory = false) {
  return invoke<RepositoryDetails>("scan_repository", { id, deepHistory });
}

export function scanAllRepositories() {
  return invoke<RepositoryOverview[]>("scan_all_repositories");
}

export function getRepositoryDetails(id: number) {
  return invoke<RepositoryDetails>("get_repository_details", { id });
}

export function deleteRepositoryPaths(
  repositoryId: number,
  relativePaths: string[],
  gitignoreEntries: string[] = [],
  bytesFreed = 0
) {
  return invoke<RepositoryDetails>("delete_repository_paths", {
    repositoryId,
    relativePaths,
    gitignoreEntries,
    bytesFreed
  });
}

export function deletePathsFromGitHistory(
  repositoryId: number,
  relativePaths: string[],
  confirmation: string,
  gitignoreEntries: string[] = [],
  bytesFreed = 0
) {
  return invoke<RepositoryDetails>("delete_paths_from_git_history", {
    repositoryId,
    relativePaths,
    confirmation,
    gitignoreEntries,
    bytesFreed
  });
}

export function getTotalBytesFreed() {
  return invoke<number>("total_bytes_freed");
}

export function forcePushRepository(repositoryId: number) {
  return invoke<void>("force_push_repository", { repositoryId });
}

export function previewForcePush(repositoryId: number) {
  return invoke<string[]>("preview_force_push", { repositoryId });
}

export function applyGitignoreEntries(repositoryId: number, entries: string[]) {
  return invoke<RepositoryDetails>("apply_gitignore_entries", { repositoryId, entries });
}

export function cancelScan(id: number) {
  return invoke<void>("cancel_scan", { id });
}

export function ignoreFindings(repositoryId: number, category: IssueCategory, paths: string[]) {
  return invoke<RepositoryDetails>("ignore_findings", { repositoryId, category, paths });
}

export function listIgnoredFindings(repositoryId: number) {
  return invoke<IgnoredFinding[]>("list_ignored_findings", { repositoryId });
}

export function unignoreFinding(id: number, repositoryId: number) {
  return invoke<RepositoryDetails>("unignore_finding", { id, repositoryId });
}
