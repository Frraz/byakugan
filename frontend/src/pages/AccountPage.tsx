import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/PageHeader";
import { ErrorBanner } from "@/components/ui/error-banner";
import { GlassPanel } from "@/components/ui/glass-panel";
import { Skeleton } from "@/components/ui/skeleton";
import { apiFetch } from "@/lib/api";
import { errorMessage } from "@/lib/errors";
import type { User } from "@/lib/types";
import { usePageTitle } from "@/hooks/usePageTitle";
import { useAuthStore } from "@/store/auth";

export function AccountPage() {
  usePageTitle("Minha conta");
  const user = useQuery({ queryKey: ["current-user"], queryFn: () => apiFetch<User>("/auth/me/") });
  useEffect(() => {
    if (user.data) useAuthStore.setState({ user: user.data });
  }, [user.data]);
  return (
    <div className="max-w-3xl">
      <PageHeader title="Minha conta" description="Identificação e permissões da sessão atual." />
      {user.isLoading ? <Skeleton className="h-40" /> : user.isError ? <ErrorBanner message={errorMessage(user.error)} onRetry={() => void user.refetch()} /> : user.data && (
        <GlassPanel>
          <dl className="grid gap-6 sm:grid-cols-2">
            {[
              ["E-mail", user.data.email],
              ["Papel", { admin: "Administrador", analyst: "Analista", viewer: "Leitura" }[user.data.role]],
              ["Estado da conta", user.data.is_active ? "Ativa" : "Inativa"],
            ].map(([label, value]) => <div key={label}><dt className="text-sm text-muted-foreground">{label}</dt><dd className="mt-1 break-all font-medium">{value}</dd></div>)}
          </dl>
          <p className="mt-6 text-sm text-muted-foreground">Para alterar seus dados ou permissões, contate o administrador do ambiente.</p>
        </GlassPanel>
      )}
    </div>
  );
}
