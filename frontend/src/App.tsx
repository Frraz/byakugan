/** Roteamento da aplicação (React Router). */

import { lazy, Suspense } from "react";
import { Skeleton } from "./components/ui/skeleton";
import { Route, Routes } from "react-router-dom";

import { AppLayout } from "./components/layout/AppLayout";
import { ProtectedRoute } from "./components/ProtectedRoute";
const AssetDetailPage = lazy(() => import("./pages/AssetDetailPage").then((module) => ({ default: module.AssetDetailPage })));
const AssetsPage = lazy(() => import("./pages/AssetsPage").then((module) => ({ default: module.AssetsPage })));
const AuditLogPage = lazy(() => import("./pages/AuditLogPage").then((module) => ({ default: module.AuditLogPage })));
const DashboardPage = lazy(() => import("./pages/DashboardPage").then((module) => ({ default: module.DashboardPage })));
const EvidencePage = lazy(() => import("./pages/EvidencePage").then((module) => ({ default: module.EvidencePage })));
const KnowledgeBasePage = lazy(() => import("./pages/KnowledgeBasePage").then((module) => ({ default: module.KnowledgeBasePage })));
const LoginPage = lazy(() => import("./pages/LoginPage").then((module) => ({ default: module.LoginPage })));
const NotFoundPage = lazy(() => import("./pages/NotFoundPage").then((module) => ({ default: module.NotFoundPage })));
const ReportsPage = lazy(() => import("./pages/ReportsPage").then((module) => ({ default: module.ReportsPage })));
const ScanDetailPage = lazy(() => import("./pages/ScanDetailPage").then((module) => ({ default: module.ScanDetailPage })));
const ScansPage = lazy(() => import("./pages/ScansPage").then((module) => ({ default: module.ScansPage })));
const TargetsPage = lazy(() => import("./pages/TargetsPage").then((module) => ({ default: module.TargetsPage })));
const VulnerabilitiesPage = lazy(() => import("./pages/VulnerabilitiesPage").then((module) => ({ default: module.VulnerabilitiesPage })));
const AccountPage = lazy(() => import("./pages/AccountPage").then((module) => ({ default: module.AccountPage })));
const UserCreatePage = lazy(() => import("./pages/UserCreatePage").then((module) => ({ default: module.UserCreatePage })));
const DesignSystemPage = import.meta.env.DEV ? lazy(() => import("./pages/DesignSystemPage").then((module) => ({ default: module.DesignSystemPage }))) : null;

export default function App() {
  return (
    <Suspense fallback={<div className="p-6" role="status" aria-label="Carregando página"><Skeleton className="h-64" /></div>}>
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
          <Route path="knowledge-base" element={<KnowledgeBasePage />} />
          <Route path="audit-log" element={<AuditLogPage />} />
          <Route path="account" element={<AccountPage />} />
          <Route path="users/new" element={<UserCreatePage />} />
          {DesignSystemPage && <Route path="design-system" element={<DesignSystemPage />} />}
          {/* Rota inexistente: sem sessão, ProtectedRoute redireciona para
              /login antes de chegar aqui; autenticado, mantém o shell
              (sidebar/topbar) visível em vez de redirecionar silenciosamente. */}
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
    </Routes>
    </Suspense>
  );
}
