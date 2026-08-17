import { useEffect, useMemo, useState } from "react";

interface ScanProgressProps {
  activeScan?: { repositoryId: number; name: string; deepHistory: boolean; startedAt: number } | null;
  onCancel: (repositoryId: number) => Promise<void>;
}

export default function ScanProgress({ activeScan, onCancel }: ScanProgressProps) {
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!activeScan) return;
    const id = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(id);
  }, [activeScan]);

  const elapsedSeconds = activeScan ? Math.floor((now - activeScan.startedAt) / 1000) : 0;
  const progress = useMemo(() => {
    if (!activeScan) return 0;
    const target = activeScan.deepHistory ? 120 : 15;
    return Math.min(96, Math.max(8, (elapsedSeconds / target) * 100));
  }, [activeScan, elapsedSeconds]);

  if (!activeScan) return null;

  return (
    <div className="scanProgress">
      <div>
        <strong>{activeScan.deepHistory ? "Long scan" : "Quick scan"}: {activeScan.name}</strong>
        <span>{elapsedSeconds}s elapsed</span>
      </div>
      <div className="progressTrack">
        <div style={{ width: `${progress}%` }} />
      </div>
      <button className="secondaryButton" onClick={() => onCancel(activeScan.repositoryId)}>
        Cancel
      </button>
    </div>
  );
}
