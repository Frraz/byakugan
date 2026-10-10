/** Roteamento da aplicação (React Router). */

import { Route, Routes } from "react-router-dom";

import { AppLayout } from "./components/layout/AppLayout";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AssetDetailPage } from "./pages/AssetDetailPage";
import { AuditLogPage } from "./pages/AuditLogPage";
import { DashboardPage } from "./pages/DashboardPage";
import { EvidencePage } from "./pages/EvidencePage";
import { KnowledgeBasePage } from "./pages/KnowledgeBasePage";
import { LoginPage } from "./pages/LoginPage";
import { NotFoundPage } from "./pages/NotFoundPage";
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
          {/* Assets deixou de ter aba própria; o detalhe do ativo continua
              acessível via drill-down do detalhe da vulnerabilidade. */}
          <Route path="assets/:id" element={<AssetDetailPage />} />
          <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="evidence" element={<EvidencePage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="knowledge-base" element={<KnowledgeBasePage />} />
          <Route path="audit-log" element={<AuditLogPage />} />
          {/* Rota inexistente: sem sessão, ProtectedRoute redireciona para
              /login antes de chegar aqui; autenticado, mantém o shell
              (sidebar/topbar) visível em vez de redirecionar silenciosamente. */}
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
  );
}
