import { open } from "@tauri-apps/plugin-dialog";
import ProjectCard from "../components/ProjectCard";
import { formatBytes } from "../components/Format";
import type { RepositoryOverview } from "../types";

interface DashboardProps {
  repositories: RepositoryOverview[];
  loading: boolean;
  scanningRepositoryIds: number[];
  totalBytesFreed: number;
  error?: string | null;
  onAddPath: (path: string) => Promise<void>;
  onScanAll: () => Promise<void>;
  onOpenRepository: (id: number) => void;
  onToggleFavorite: (id: number, favorite: boolean) => Promise<void>;
}

export default function Dashboard({
  repositories,
  loading,
  scanningRepositoryIds,
  totalBytesFreed,
  error,
  onAddPath,
  onScanAll,
  onOpenRepository,
  onToggleFavorite
}: DashboardProps) {
  const scannedRepositories = repositories.filter((repository) => repository.latest_scan);
  const totalSize = scannedRepositories.reduce(
    (sum, repository) => sum + (repository.latest_scan?.total_size ?? 0),
    0
  );
  const totalPotentialCleanup = scannedRepositories.reduce(
    (sum, repository) => sum + (repository.latest_scan?.potential_cleanup ?? 0),
    0
  );
  const averageScore =
    scannedRepositories.length > 0
      ? Math.round(
          scannedRepositories.reduce((sum, repository) => sum + (repository.latest_scan?.score ?? 0), 0) /
            scannedRepositories.length
        )
      : null;

  async function addProject() {
    const selected = await open({
      directory: true,
      multiple: false,
      title: "Add Git repository"
    });

    if (typeof selected === "string") {
      await onAddPath(selected);
    }
  }

  return (
    <main className="screen">
      <header className="topBar">
        <div>
          <h1>Repoglance</h1>
          <p>Local Git repository health</p>
        </div>
        <div className="actions">
          <button className="secondaryButton" onClick={onScanAll} disabled={loading || repositories.length === 0}>
            Scan All
          </button>
          <button className="iconButton" onClick={addProject} disabled={loading} aria-label="Add project" title="Add project">
            +
          </button>
        </div>
      </header>

      {repositories.length > 0 ? (
        <section className="summaryBand">
          <div className="statsGrid">
            <div>
              <span>Repositories scanned</span>
              <strong>
                {scannedRepositories.length}/{repositories.length}
              </strong>
            </div>
            <div>
              <span>Total size</span>
              <strong>{formatBytes(totalSize)}</strong>
            </div>
            <div>
              <span>Cleanup potential</span>
              <strong>{formatBytes(totalPotentialCleanup)}</strong>
            </div>
            <div>
              <span>Average score</span>
              <strong>{averageScore ?? "--"}</strong>
            </div>
            <div>
              <span>Freed so far</span>
              <strong>{formatBytes(totalBytesFreed)}</strong>
            </div>
          </div>
        </section>
      ) : null}

      <section className="sectionHeader">
        <h2>Projects</h2>
      </section>

      {error ? <div className="notice error">{error}</div> : null}

      {repositories.length === 0 ? (
        <div className="emptyState">
          <h2>No repositories added yet.</h2>
          <p>Add a local Git repository to get started.</p>
          <button onClick={addProject} disabled={loading}>Add Project</button>
        </div>
      ) : (
        <div className="projectList">
          {repositories.map((repository) => (
            <ProjectCard
              key={repository.id}
              repository={repository}
              scanning={scanningRepositoryIds.includes(repository.id)}
              onOpen={() => onOpenRepository(repository.id)}
              onToggleFavorite={() => onToggleFavorite(repository.id, !repository.favorite)}
            />
          ))}
        </div>
      )}
    </main>
  );
}
