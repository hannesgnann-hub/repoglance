import { open } from "@tauri-apps/plugin-shell";
import type { MouseEvent, ReactNode } from "react";

interface ExternalLinkProps {
  href: string;
  className?: string;
  children: ReactNode;
}

/**
 * A plain `<a href="https://...">` does not open the system browser inside a
 * Tauri webview - it just tries (and fails) to navigate the app's own
 * window. This opens the URL via the shell plugin instead.
 */
export default function ExternalLink({ href, className, children }: ExternalLinkProps) {
  function handleClick(event: MouseEvent<HTMLAnchorElement>) {
    event.preventDefault();
    void open(href);
  }

  return (
    <a href={href} className={className} onClick={handleClick}>
      {children}
    </a>
  );
}
