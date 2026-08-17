import { open } from "@tauri-apps/plugin-dialog";
import ProjectCard from "../components/ProjectCard";
import type { RepositoryOverview } from "../types";

interface DashboardProps {
  repositories: RepositoryOverview[];
  loading: boolean;
  scanningRepositoryIds: number[];
  error?: string | null;
  onAddPath: (path: string) => Promise<void>;
  onScanAll: () => Promise<void>;
  onOpenRepository: (id: number) => void;
}

export default function Dashboard({
  repositories,
  loading,
  scanningRepositoryIds,
  error,
  onAddPath,
  onScanAll,
  onOpenRepository
}: DashboardProps) {
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
            />
          ))}
        </div>
      )}
    </main>
  );
}
