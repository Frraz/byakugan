/** Tela de login — identidade da marca, dark command-center. */

import { useEffect, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { loginSchema } from "@/lib/forms";
import { FieldError } from "@/components/ui/field-error";
import { Eye, EyeOff } from "lucide-react";

import { Mark } from "@/components/brand/Logo";
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
  const { register, handleSubmit, resetField, formState: { errors } } = useForm<{ email: string; password: string }>({ resolver: zodResolver(loginSchema), defaultValues: { email: "", password: "" } });
  const [showPassword, setShowPassword] = useState(false);
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from;
  const destination = from?.startsWith("/") && !from.startsWith("//") && !from.includes("\\") && !from.startsWith("/login") ? from : "/";
  // Capturado uma única vez: se o usuário chegou aqui por refresh falho (não
  // por logout manual), mostramos o aviso e limpamos a flag para não repetir
  // em um próximo acesso à página.
  const [showExpiredNotice] = useState(() => useAuthStore.getState().sessionExpired);
  useEffect(() => {
    if (useAuthStore.getState().sessionExpired) useAuthStore.getState().setSessionExpired(false);
  }, []);

  if (access) return <Navigate to={destination} replace />;

  const onSubmit = ({ email, password }: { email: string; password: string }) => {
    if (login.isPending) return;
    login.mutate({ email: email.trim(), password }, { onSuccess: () => { resetField("password"); navigate(destination, { replace: true }); } });
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <Mark size={56} className="text-primary" />
          <h1 className="mt-4 text-2xl font-semibold tracking-[0.18em] text-foreground">
            BYAKUGAN
          </h1>
          <p className="text-[11px] font-medium tracking-[0.28em] text-muted-foreground">
            SECURITY ASSESSMENT
          </p>
        </div>

        {showExpiredNotice && (
          <ErrorBanner
            className="mb-4"
            message="Sua sessão expirou. Faça login novamente para continuar."
          />
        )}

        <form noValidate onSubmit={handleSubmit(onSubmit)} className="glass space-y-4 p-6">
          <div className="space-y-1.5">
            <Label htmlFor="login-email">Email</Label>
            <Input
              id="login-email"
              type="email"
              autoComplete="username"
              required
              autoFocus
              {...register("email")}
              aria-invalid={Boolean(errors.email)}
              aria-describedby="login-email-error"
              disabled={login.isPending}
              placeholder="analyst@empresa.com"
            />
          </div>
          <FieldError id="login-email-error" message={errors.email?.message} />
          <div className="space-y-1.5">
            <Label htmlFor="login-password">Senha</Label>
            <Input
              id="login-password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              required
              {...register("password")}
              aria-invalid={Boolean(errors.password)}
              aria-describedby="login-password-error"
              disabled={login.isPending}
              placeholder="••••••••••"
            />
            <Button type="button" variant="ghost" size="sm" aria-controls="login-password" aria-pressed={showPassword} onClick={() => setShowPassword((visible) => !visible)}>
              {showPassword ? <EyeOff /> : <Eye />} {showPassword ? "Ocultar senha" : "Mostrar senha"}
            </Button>
          </div>

          <FieldError id="login-password-error" message={errors.password?.message} />
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
