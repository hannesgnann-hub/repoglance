import { invoke } from "@tauri-apps/api/core";
import type { RepositoryDetails, RepositoryOverview } from "../types";

export function listRepositories() {
  return invoke<RepositoryOverview[]>("list_repositories");
}

export function addRepository(path: string) {
  return invoke<RepositoryOverview>("add_repository", { path });
}

export function removeRepository(id: number) {
  return invoke<void>("remove_repository", { id });
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

export function deleteRepositoryPath(repositoryId: number, relativePath: string, gitignoreEntry?: string) {
  return invoke<RepositoryDetails>("delete_repository_path", {
    repositoryId,
    relativePath,
    gitignoreEntry: gitignoreEntry ?? null
  });
}

export function deletePathFromGitHistory(repositoryId: number, relativePath: string, confirmation: string) {
  return invoke<RepositoryDetails>("delete_path_from_git_history", {
    repositoryId,
    relativePath,
    confirmation
  });
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
