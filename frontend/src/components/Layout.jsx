import Navbar from "./Navbar";
import ExecutionScanNotice from "./ExecutionScanNotice";
import { useLocation } from "react-router-dom";
import CICDNavigation, { isCICDPath } from "./CICDNavigation";

export default function Layout({ children }) {
  const { pathname } = useLocation();
  return (
    <div className="min-h-screen app-shell">
      <Navbar />
      <main className="p-6">
        {isCICDPath(pathname) && <CICDNavigation />}
        <ExecutionScanNotice />
        {children}
      </main>
    </div>
  );
}
