/** Tela de login — identidade da marca, dark command-center. */

import { type FormEvent, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";

import { EyeMark } from "../components/brand/Logo";
import { Button, ErrorBanner, Field, Input } from "../components/ui";
import { useLogin } from "../hooks/useAuth";
import { useAuthStore } from "../store/auth";

export function LoginPage() {
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
          <EyeMark size={72} className="text-accent" />
          <h1 className="mt-4 text-3xl font-extrabold tracking-[0.2em] text-foreground">
            BYAKUGAN
          </h1>
          <p className="text-[11px] font-semibold tracking-[0.32em] text-primary">
            CYBERSECURITY PLATFORM
          </p>
          <p className="mt-3 text-sm text-muted">See Everything. Detect Everything.</p>
        </div>

        <form onSubmit={onSubmit} className="glass space-y-4 p-6">
          <Field label="Email">
            <Input
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@empresa.com"
            />
          </Field>
          <Field label="Senha">
            <Input
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••"
            />
          </Field>

          {login.isError && <ErrorBanner message={(login.error as Error).message} />}

          <Button type="submit" className="w-full" disabled={login.isPending}>
            {login.isPending ? "Entrando…" : "Entrar"}
          </Button>
        </form>

        <p className="mt-6 text-center text-[11px] leading-relaxed text-muted">
          Uso autorizado apenas. Toda análise exige autorização documentada.
        </p>
      </div>
    </div>
  );
}
