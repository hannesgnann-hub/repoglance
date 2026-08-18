interface LoadingIndicatorProps {
  label?: string;
}

export default function LoadingIndicator({ label = "Working..." }: LoadingIndicatorProps) {
  return (
    <div className="loadingIndicator" role="status" aria-live="polite">
      <span className="loadingSpinner" aria-hidden="true" />
      <strong>{label}</strong>
    </div>
  );
}
