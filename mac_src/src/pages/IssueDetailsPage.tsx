import { useState } from "react";
import { formatBytes } from "../components/Format";
import type { Issue, RepositoryDetails } from "../types";

interface IssueDetailsPageProps {
  details: RepositoryDetails;
  issue: Issue;
  loading: boolean;
  onBack: () => void;
  onDeletePath: (relativePath: string) => Promise<void>;
  onDeleteFromGitHistory: (relativePath: string) => Promise<void>;
  onForcePush: () => Promise<void>;
  onPreviewForcePush: () => Promise<string[]>;
  onApplyGitignoreEntries: (entries: string[]) => Promise<void>;
  onRunLongHistoryScan: () => Promise<void>;
}

export default function IssueDetailsPage({
  details,
  issue,
  loading,
  onBack,
  onDeletePath,
  onDeleteFromGitHistory,
  onForcePush,
  onPreviewForcePush,
  onApplyGitignoreEntries,
  onRunLongHistoryScan
}: IssueDetailsPageProps) {
  const gitignoreEntries = issue.category === "gitignore" ? issue.affected_paths.map((file) => file.path) : [];
  const historySkipped = issue.category === "historical_large_file" && issue.title === "History scan skipped";
  const [gitDialog, setGitDialog] = useState<{
    path: string;
    step: "ready" | "deleted" | "pushed";
    error?: string | null;
  } | null>(null);
  const [hiddenGitDeletedPaths, setHiddenGitDeletedPaths] = useState<Set<string>>(new Set());
  const visibleAffectedPaths = issue.affected_paths.filter((file) => !hiddenGitDeletedPaths.has(file.path));
  const [pushPreview, setPushPreview] = useState<{
    loading: boolean;
    lines: string[];
    error: string | null;
  }>({ loading: false, lines: [], error: null });

  function fileStateLabel(currentlyExists: boolean) {
    if (issue.category === "gitignore") return "Recommended entry";
    if (issue.category === "branch") return "Local branch";
    return currentlyExists ? "Current repository" : "Deleted from working tree";
  }

  async function deletePath(relativePath: string) {
    const confirmed = window.confirm(
      `Delete this path from the working tree?\n\n${relativePath}\n\nThis cannot remove data from Git history.`
    );

    if (confirmed) {
      await onDeletePath(relativePath);
    }
  }

  function openDeleteOnGitDialog(relativePath: string) {
    setGitDialog({ path: relativePath, step: "ready", error: null });
    setPushPreview({ loading: false, lines: [], error: null });
  }

  async function runDeleteOnGit() {
    if (!gitDialog) return;
    try {
      setGitDialog({ ...gitDialog, error: null });
      await onDeleteFromGitHistory(gitDialog.path);
      setHiddenGitDeletedPaths((paths) => new Set(paths).add(gitDialog.path));
      setGitDialog({ ...gitDialog, step: "deleted", error: null });
      void loadPushPreview();
    } catch (err) {
      setGitDialog({
        ...gitDialog,
        error: err instanceof Error ? err.message : String(err)
      });
    }
  }

  async function loadPushPreview() {
    setPushPreview({ loading: true, lines: [], error: null });
    try {
      const lines = await onPreviewForcePush();
      setPushPreview({ loading: false, lines, error: null });
    } catch (err) {
      setPushPreview({
        loading: false,
        lines: [],
        error: err instanceof Error ? err.message : String(err)
      });
    }
  }

  async function runForcePush() {
    if (!gitDialog) return;
    try {
      setGitDialog({ ...gitDialog, error: null });
      await onForcePush();
      setGitDialog({ ...gitDialog, step: "pushed", error: null });
    } catch (err) {
      setGitDialog({
        ...gitDialog,
        error: err instanceof Error ? err.message : String(err)
      });
    }
  }

  return (
    <>
      <main className="screen narrow">
        <header className="topBar">
          <div className="titleWithBack">
            <button className="plainButton" onClick={onBack}>‹ {details.repository.name}</button>
            <div>
              <h1>{issue.title}</h1>
              <p>{formatBytes(issue.estimated_cleanup_bytes)} potentially removable</p>
            </div>
          </div>
        </header>

        <section className="detailBlock">
          <h2>Why this matters</h2>
          <p>{issue.description}</p>
        </section>

        <section className="detailBlock">
          <h2>Affected files</h2>
          <div className="fileList">
            {visibleAffectedPaths.length === 0 ? (
              <div className="emptyPanel">No remaining file paths recorded for this issue.</div>
            ) : (
              visibleAffectedPaths.map((file) => (
                <div key={`${file.path}-${file.size}-${file.note ?? ""}`}>
                  <div>
                    <strong>{file.path}</strong>
                    <span>{fileStateLabel(file.currently_exists)}</span>
                    {file.note ? <small>{file.note}</small> : null}
                  </div>
                  <div className="fileActions">
                    <em>{formatBytes(file.size)}</em>
                    {file.currently_exists ? (
                      <div className="buttonStack">
                        <button className="dangerButton" onClick={() => deletePath(file.path)} disabled={loading}>
                          Delete
                        </button>
                        <button className="historyDangerButton" onClick={() => openDeleteOnGitDialog(file.path)} disabled={loading}>
                          Delete on Git
                        </button>
                      </div>
                    ) : null}
                    {!file.currently_exists && issue.category === "historical_large_file" ? (
                      <button className="historyDangerButton" onClick={() => openDeleteOnGitDialog(file.path)} disabled={loading}>
                        Delete on Git
                      </button>
                    ) : null}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        {gitignoreEntries.length > 0 ? (
          <section className="detailBlock actionBlock">
            <h2>Apply recommendation</h2>
            <p>Add these entries to this repository's `.gitignore` and scan again.</p>
            <button onClick={() => onApplyGitignoreEntries(gitignoreEntries)} disabled={loading}>
              Add to .gitignore
            </button>
          </section>
        ) : null}

        {historySkipped ? (
          <section className="detailBlock actionBlock">
            <h2>Long history scan</h2>
            <p>Run a slower history scan with a larger object limit. You can cancel it while it runs.</p>
            <button onClick={onRunLongHistoryScan} disabled={loading}>
              Run long scan
            </button>
          </section>
        ) : null}

        <section className="detailBlock">
          <h2>Recommendation</h2>
          <p>
            Delete removes current working-tree files or directories only. Delete on Git removes the
            selected path from Git history with a clean worktree requirement, then runs Git cleanup.
            After Force Push, future clones can become smaller.
          </p>
        </section>
      </main>

      {gitDialog ? (
        <div className="modalBackdrop" role="dialog" aria-modal="true" aria-labelledby="git-delete-title">
          <div className="gitDeleteDialog">
            <header>
              <h2 id="git-delete-title">Delete on Git</h2>
              <button className="plainButton" onClick={() => setGitDialog(null)} disabled={loading}>
                Close
              </button>
            </header>

            <div className="dialogPath">
              <span>Path</span>
              <strong>{gitDialog.path}</strong>
            </div>

            <div className="dialogSteps">
              <div className={gitDialog.step === "ready" ? "active" : ""}>
                <strong>1. Delete</strong>
                <span>Rewrites local Git history, cleans `.git`, and removes the current checkout path.</span>
              </div>
              <div className={gitDialog.step === "deleted" || gitDialog.step === "pushed" ? "active" : ""}>
                <strong>2. Force Push</strong>
                <span>Pushes the rewritten history to the remote so future clones shrink.</span>
              </div>
            </div>

            {gitDialog.step !== "ready" ? (
              <div className="dialogPreview">
                <strong>What Force Push will change on the remote</strong>
                {pushPreview.loading ? <p>Checking the remote…</p> : null}
                {pushPreview.error ? (
                  <p className="dialogError">
                    Could not preview remote changes: {pushPreview.error}. You can still force push, but you
                    will not see what changes beforehand.
                  </p>
                ) : null}
                {!pushPreview.loading && !pushPreview.error ? (
                  pushPreview.lines.length === 0 ? (
                    <p>No ref changes detected, or the remote already matches.</p>
                  ) : (
                    <ul>
                      {pushPreview.lines.map((line) => (
                        <li key={line}>{line}</li>
                      ))}
                    </ul>
                  )
                ) : null}
              </div>
            ) : null}

            {gitDialog.error ? <div className="dialogError">{gitDialog.error}</div> : null}

            <div className="dialogActions">
              <button
                className="dangerButton"
                onClick={runDeleteOnGit}
                disabled={loading || gitDialog.step !== "ready"}
              >
                Delete
              </button>
              <button
                className="historyDangerButton"
                onClick={runForcePush}
                disabled={loading || gitDialog.step === "ready" || gitDialog.step === "pushed"}
              >
                Force Push
              </button>
            </div>

            {gitDialog.step === "pushed" ? (
              <div className="dialogSuccess">Done. The rewritten history was force-pushed.</div>
            ) : null}
          </div>
        </div>
      ) : null}
    </>
  );
}
