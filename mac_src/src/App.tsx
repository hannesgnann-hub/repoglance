import { useEffect, useMemo, useState } from "react";
import LoadingIndicator from "./components/LoadingIndicator";
import ScanProgress from "./components/ScanProgress";
import Dashboard from "./pages/Dashboard";
import IssueDetailsPage from "./pages/IssueDetailsPage";
import RepositoryDetailsPage from "./pages/RepositoryDetailsPage";
import {
  addRepository,
  applyGitignoreEntries,
  cancelScan,
  deletePathFromGitHistory,
  deleteRepositoryPath,
  forcePushRepository,
  getRepositoryDetails,
  listRepositories,
  previewForcePush,
  removeRepository,
  scanAllRepositories,
  scanRepository
} from "./services/repoglance";
import type { Issue, RepositoryDetails, RepositoryOverview } from "./types";

type Route =
  | { name: "dashboard" }
  | { name: "repository"; id: number }
  | { name: "issue"; repositoryId: number; issueId: number };

export default function App() {
  const [route, setRoute] = useState<Route>({ name: "dashboard" });
  const [repositories, setRepositories] = useState<RepositoryOverview[]>([]);
  const [details, setDetails] = useState<RepositoryDetails | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingLabel, setLoadingLabel] = useState("Working...");
  const [scanningRepositoryIds, setScanningRepositoryIds] = useState<number[]>([]);
  const [activeScan, setActiveScan] = useState<{ repositoryId: number; name: string; deepHistory: boolean; startedAt: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedIssue = useMemo(() => {
    if (route.name !== "issue" || !details) return null;
    return details.issues.find((issue) => issue.id === route.issueId) ?? null;
  }, [details, route]);

  const progress = (
    <ScanProgress
      activeScan={activeScan}
      onCancel={(repositoryId) =>
        run(async () => {
          await cancelScan(repositoryId);
          setActiveScan(null);
          setScanningRepositoryIds((ids) => ids.filter((id) => id !== repositoryId));
        }, "Cancelling scan...")
      }
    />
  );
  const loadingIndicator = loading ? <LoadingIndicator label={activeScan ? "Scanning..." : loadingLabel} /> : null;

  async function refreshRepositories() {
    const next = await listRepositories();
    setRepositories(next);
  }

  async function refreshDetails(id: number) {
    const next = await getRepositoryDetails(id);
    setDetails(next);
  }

  async function run(action: () => Promise<void>, label = "Working...") {
    setLoadingLabel(label);
    setLoading(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function runAndThrow(action: () => Promise<void>, label = "Working...") {
    setLoadingLabel(label);
    setLoading(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      throw err;
    } finally {
      setLoading(false);
    }
  }

  async function scanAndRefresh(id: number, deepHistory = false) {
    const repositoryName =
      repositories.find((repository) => repository.id === id)?.name ??
      details?.repository.name ??
      "Repository";
    setScanningRepositoryIds((ids) => (ids.includes(id) ? ids : [...ids, id]));
    setActiveScan({ repositoryId: id, name: repositoryName, deepHistory, startedAt: Date.now() });
    try {
      const next = await scanRepository(id, deepHistory);
      if (route.name === "repository" && route.id === id) {
        setDetails(next);
      }
    } finally {
      setScanningRepositoryIds((ids) => ids.filter((value) => value !== id));
      setActiveScan((scan) => (scan?.repositoryId === id ? null : scan));
    }
    await refreshRepositories();
  }

  useEffect(() => {
    void run(refreshRepositories, "Loading projects...");
  }, []);

  useEffect(() => {
    if (route.name === "repository") {
      void run(() => refreshDetails(route.id), "Loading repository...");
    }
    if (route.name === "dashboard") {
      setDetails(null);
    }
  }, [route]);

  if (route.name === "issue" && details && selectedIssue) {
    return (
      <>
        {progress}
        {loadingIndicator}
        {error ? <div className="floatingNotice">{error}</div> : null}
        <IssueDetailsPage
          details={details}
          issue={selectedIssue}
          loading={loading}
          onBack={() => setRoute({ name: "repository", id: route.repositoryId })}
          onDeletePath={(relativePath) =>
            run(async () => {
              const next = await deleteRepositoryPath(route.repositoryId, relativePath);
              setDetails(next);
              await refreshRepositories();
              const refreshedIssue = next.issues.find((issue) => issue.id === route.issueId);
              if (!refreshedIssue) {
                setRoute({ name: "repository", id: route.repositoryId });
              }
            }, "Deleting path...")
          }
          onDeleteFromGitHistory={(relativePath) =>
            runAndThrow(async () => {
              await deletePathFromGitHistory(route.repositoryId, relativePath, "REWRITE HISTORY");
              await refreshRepositories();
            }, "Deleting on Git...")
          }
          onPreviewForcePush={() => previewForcePush(route.repositoryId)}
          onForcePush={() =>
            runAndThrow(async () => {
              await forcePushRepository(route.repositoryId);
              const next = await getRepositoryDetails(route.repositoryId);
              setDetails(next);
              await refreshRepositories();
              const refreshedIssue = next.issues.find((issue) => issue.id === route.issueId);
              if (!refreshedIssue) {
                setRoute({ name: "repository", id: route.repositoryId });
              }
            }, "Force pushing...")
          }
          onApplyGitignoreEntries={(entries) =>
            run(async () => {
              const next = await applyGitignoreEntries(route.repositoryId, entries);
              setDetails(next);
              await refreshRepositories();
              setRoute({ name: "repository", id: route.repositoryId });
            }, "Updating .gitignore...")
          }
          onRunLongHistoryScan={() => run(() => scanAndRefresh(route.repositoryId, true), "Scanning...")}
        />
      </>
    );
  }

  if (route.name === "repository" && details) {
    return (
      <>
        {progress}
        {loadingIndicator}
        {error ? <div className="floatingNotice">{error}</div> : null}
        <RepositoryDetailsPage
          details={details}
          loading={loading}
          onBack={() => setRoute({ name: "dashboard" })}
          onOpenIssue={(issue) => setRoute({ name: "issue", repositoryId: route.id, issueId: issue.id })}
          onRemove={() =>
            run(async () => {
              await removeRepository(route.id);
              await refreshRepositories();
              setRoute({ name: "dashboard" });
            }, "Removing repository...")
          }
          onScan={() =>
            run(async () => {
              await scanAndRefresh(route.id);
            }, "Scanning...")
          }
          onLongScan={() =>
            run(async () => {
              await scanAndRefresh(route.id, true);
            }, "Scanning...")
          }
        />
      </>
    );
  }

  return (
    <>
      {progress}
      {loadingIndicator}
      <Dashboard
        repositories={repositories}
        loading={loading}
        scanningRepositoryIds={scanningRepositoryIds}
        error={error}
        onOpenRepository={(id) => setRoute({ name: "repository", id })}
        onAddPath={(path) =>
          run(async () => {
            const repository = await addRepository(path);
            setRepositories((items) => (items.some((item) => item.id === repository.id) ? items : [...items, repository]));
            await refreshRepositories();
            await scanAndRefresh(repository.id);
          }, "Adding repository...")
        }
        onScanAll={() =>
          run(async () => {
            setScanningRepositoryIds(
              repositories.filter((repository) => !repository.missing).map((repository) => repository.id)
            );
            try {
              const next = await scanAllRepositories();
              setRepositories(next);
            } finally {
              setScanningRepositoryIds([]);
            }
          }, "Scanning repositories...")
        }
      />
    </>
  );
}
