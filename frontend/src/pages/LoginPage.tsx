/** Tela de login — identidade da marca, dark command-center. */

import { type FormEvent, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";

import { EyeMark } from "@/components/brand/Logo";
import { Button } from "@/components/ui/button";
import { ErrorBanner } from "@/components/ui/error-banner";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useLogin } from "@/hooks/useAuth";
import { usePageTitle } from "@/hooks/usePageTitle";
import { errorMessage } from "@/lib/errors";
import { useAuthStore } from "@/store/auth";

export function LoginPage() {
  usePageTitle("Entrar");
  const access = useAuthStore((s) => s.access);
  const navigate = useNavigate();
  const login = useLogin();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  if (access) return <Navigate to="/" replace />;

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    login.mutate({ email, password }, { onSuccess: () => navigate("/") });
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <EyeMark size={108} className="text-accent" />
          <h1 className="mt-4 text-3xl font-extrabold tracking-[0.2em] text-foreground">
            BYAKUGAN
          </h1>
          <p className="text-[11px] font-semibold tracking-[0.32em] text-primary">
            CYBERSECURITY PLATFORM
          </p>
          <p className="mt-3 text-sm text-muted-foreground">See Everything. Detect Everything.</p>
        </div>

        <form onSubmit={onSubmit} className="glass space-y-4 p-6">
          <div className="space-y-1.5">
            <Label htmlFor="login-email">Email</Label>
            <Input
              id="login-email"
              type="email"
              autoComplete="username"
              required
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@empresa.com"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="login-password">Senha</Label>
            <Input
              id="login-password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••"
            />
          </div>

          {login.isError && <ErrorBanner message={errorMessage(login.error)} />}

          <Button type="submit" className="w-full" disabled={login.isPending}>
            {login.isPending ? "Entrando…" : "Entrar"}
          </Button>
        </form>

        <p className="mt-6 text-center text-[11px] leading-relaxed text-muted-foreground">
          Uso autorizado apenas. Toda análise exige autorização documentada.
        </p>
      </div>
    </div>
  );
}
