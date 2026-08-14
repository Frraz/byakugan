/** Roteamento da aplicação (React Router). */

import { Navigate, Route, Routes } from "react-router-dom";

import { AppLayout } from "./components/layout/AppLayout";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AssetDetailPage } from "./pages/AssetDetailPage";
import { AssetsPage } from "./pages/AssetsPage";
import { DashboardPage } from "./pages/DashboardPage";
import { EvidencePage } from "./pages/EvidencePage";
import { KnowledgeBasePage } from "./pages/KnowledgeBasePage";
import { LoginPage } from "./pages/LoginPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { ScansPage } from "./pages/ScansPage";
import { TargetsPage } from "./pages/TargetsPage";
import { VulnerabilitiesPage } from "./pages/VulnerabilitiesPage";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route index element={<DashboardPage />} />
          <Route path="targets" element={<TargetsPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/:id" element={<ScanDetailPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="assets/:id" element={<AssetDetailPage />} />
          <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="evidence" element={<EvidencePage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="knowledge" element={<KnowledgeBasePage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
