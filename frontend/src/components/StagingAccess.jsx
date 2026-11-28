import { useState } from "react";
import { Copy, ExternalLink, Server } from "lucide-react";
import { stagingAccess } from "../utils/stagingAccess";

// Staging link with its scope and the copyable port-forward command for a Windows browser.
export default function StagingAccess({ projectId, appName, stagingUrl, compact = false }) {
  const [copied, setCopied] = useState(false);
  const a = stagingAccess({ projectId, appName, stagingUrl });
  if (!a.url) return null;
  const copy = async () => {
    try { await navigator.clipboard.writeText(a.command); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { setCopied(false); }
  };
  return (
    <div className={`text-xs space-y-1 ${compact ? "" : "max-w-xl"}`}>
      <a href={a.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 hover:bg-green-500/20 transition-colors break-all">
        <Server size={12} />Live Staging: {a.url}<ExternalLink size={11} />
      </a>
      <p className="text-[var(--text-tertiary)]">URL {a.label}. From Windows, run this in WSL, then open {a.localUrl || "the forwarded port"}:</p>
      {a.command ? (
        <div className="flex items-center gap-2">
          <code className="font-mono bg-black/30 border border-[var(--border-subtle)] rounded px-2 py-1 break-all select-all">{a.command}</code>
          <button type="button" onClick={copy} className="secondary-btn inline-flex items-center gap-1 px-2 py-1" aria-label="Copy port-forward command"><Copy size={12} />{copied ? "Copied" : "Copy"}</button>
        </div>
      ) : <p className="text-[var(--text-tertiary)]">Port-forward command unavailable: the deployment record has no app name.</p>}
    </div>
  );
}
