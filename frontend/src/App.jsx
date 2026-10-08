import { Navigate, Route, BrowserRouter as Router, Routes, useLocation } from "react-router-dom";
import { useAuth } from "./context/AuthContext";
import Layout from "./components/Layout";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Register from "./pages/Register";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Dashboard from "./pages/Dashboard";
import ProjectsPage from "./pages/ProjectsPage";
import ProjectDetails from "./pages/ProjectDetails";
import SASTResults from "./pages/SASTResults";
import DASTResults from "./pages/DASTResults";
import CICDPipeline from "./pages/CICDPipeline";
import Dependencies from "./pages/Dependencies";
import IaCSecurity from "./pages/IaCSecurity";
import CloudDeployment from "./pages/CloudDeployment";
import KubernetesSecurity from "./pages/KubernetesSecurity";
import ComplianceDashboard from "./pages/ComplianceDashboard";
import MonitoringAlerts from "./pages/MonitoringAlerts";
import SecretsManagement from "./pages/SecretsManagement";
import ProfileSettings from "./pages/ProfileSettings";

function ProtectedRoute({ children }) {
  const { loading } = useAuth();
  const location = useLocation();
  const token = localStorage.getItem("cloudsentinel_token");
  if (loading) return <div className="min-h-screen grid place-items-center">Loading...</div>;
  if (!token) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <Layout>{children}</Layout>;
}

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/landing" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/projects" element={<ProtectedRoute><ProjectsPage /></ProtectedRoute>} />
        <Route path="/projects/:id" element={<ProtectedRoute><ProjectDetails /></ProtectedRoute>} />
        <Route path="/projects/:id/sast" element={<ProtectedRoute><SASTResults /></ProtectedRoute>} />
        <Route path="/projects/:id/dast" element={<ProtectedRoute><DASTResults /></ProtectedRoute>} />
        <Route path="/projects/:id/iac" element={<ProtectedRoute><IaCSecurity /></ProtectedRoute>} />
        <Route path="/cicd" element={<ProtectedRoute><CICDPipeline /></ProtectedRoute>} />
        <Route path="/dependencies" element={<ProtectedRoute><Dependencies /></ProtectedRoute>} />
        <Route path="/iac" element={<ProtectedRoute><IaCSecurity /></ProtectedRoute>} />
        <Route path="/cloud" element={<ProtectedRoute><CloudDeployment /></ProtectedRoute>} />
        <Route path="/kubernetes" element={<ProtectedRoute><KubernetesSecurity /></ProtectedRoute>} />
        <Route path="/compliance" element={<ProtectedRoute><ComplianceDashboard /></ProtectedRoute>} />
        <Route path="/monitoring" element={<ProtectedRoute><MonitoringAlerts /></ProtectedRoute>} />
        <Route path="/secrets" element={<ProtectedRoute><SecretsManagement /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute><ProfileSettings /></ProtectedRoute>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}
