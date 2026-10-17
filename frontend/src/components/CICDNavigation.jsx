import { Link, useLocation } from "react-router-dom";

export function isCICDPath(pathname) {
  return ["/cicd", "/dependencies", "/iac"].includes(pathname) ||
    /^\/projects\/[^/]+\/(iac|executions\/[^/]+\/report)\/?$/.test(pathname);
}

export default function CICDNavigation() {
  const { pathname } = useLocation();
  const activePath = pathname.endsWith("/iac") ? "/iac" :
    pathname === "/dependencies" ? "/dependencies" : "/cicd";

  return (
    <nav aria-label="CI/CD sections" className="flex flex-wrap gap-2 mb-6">
      {[["/cicd", "Pipeline History"]].map(([to, label]) => (
        <Link
          key={to}
          to={to}
          aria-current={activePath === to ? "page" : undefined}
          className={`px-4 py-2 rounded-md text-sm border transition-colors ${activePath === to
            ? "border-[var(--accent-green)] text-[var(--accent-green)] bg-[rgba(47,111,79,0.10)]"
            : "border-[var(--border-subtle)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"}`}
        >
          {label}
        </Link>
      ))}
    </nav>
  );
}
