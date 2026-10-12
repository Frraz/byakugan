import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { z } from "zod";
import { toast } from "sonner";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { ErrorBanner } from "@/components/ui/error-banner";
import { FieldError } from "@/components/ui/field-error";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { usePermissions } from "@/hooks/usePermissions";
import { usePageTitle } from "@/hooks/usePageTitle";
import { apiFetch } from "@/lib/api";
import { errorMessage, fieldErrors } from "@/lib/errors";
import { registerSchema } from "@/lib/forms";

type Values = z.infer<typeof registerSchema>;
const defaults: Values = { email: "", password: "", role: "viewer" };

export function UserCreatePage() {
  usePageTitle("Cadastrar usuário");
  const { isAdmin } = usePermissions();
  const { register, handleSubmit, reset, setError, formState: { errors } } = useForm<Values>({ resolver: zodResolver(registerSchema), defaultValues: defaults });
  const create = useMutation({ mutationFn: (values: Values) => apiFetch("/auth/register/", { method: "POST", body: values }) });
  const submit = (values: Values) => {
    if (create.isPending) return;
    create.mutate(values, {
      onSuccess: () => { toast.success("Usuário cadastrado."); reset(defaults); },
      onError: (error) => {
        for (const [field, message] of Object.entries(fieldErrors(error))) if (field in defaults) setError(field as keyof Values, { message });
      },
    });
  };
  return <div className="max-w-2xl">
    <PageHeader title="Cadastrar usuário" description="Crie uma conta com o acesso necessário ao ambiente." />
    {!isAdmin ? <ErrorBanner message="Acesso restrito a administradores." /> : <form className="glass space-y-5 p-5" noValidate onSubmit={handleSubmit(submit)}>
      <div className="space-y-2"><Label htmlFor="user-email">E-mail</Label><Input id="user-email" type="email" autoComplete="off" {...register("email")} disabled={create.isPending} aria-invalid={Boolean(errors.email)} aria-describedby="user-email-error" /><FieldError id="user-email-error" message={errors.email?.message} /></div>
      <div className="space-y-2"><Label htmlFor="user-password">Senha inicial</Label><Input id="user-password" type="password" autoComplete="new-password" {...register("password")} disabled={create.isPending} aria-invalid={Boolean(errors.password)} aria-describedby="user-password-error user-password-hint" /><p id="user-password-hint" className="text-sm text-muted-foreground">Use pelo menos 12 caracteres. O servidor também verifica a política de senhas.</p><FieldError id="user-password-error" message={errors.password?.message} /></div>
      <div className="space-y-2"><Label htmlFor="user-role">Papel</Label><select id="user-role" {...register("role")} disabled={create.isPending} className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"><option value="viewer">Leitura — consultar resultados</option><option value="analyst">Analista — executar e analisar scans</option><option value="admin">Administrador — acesso total e exclusões</option></select></div>
      {create.isError && <ErrorBanner message={errorMessage(create.error)} />}
      {create.isSuccess && <p role="status" className="text-sm text-success">Conta criada. Você pode cadastrar outro usuário.</p>}
      <Button type="submit" disabled={create.isPending}>{create.isPending ? "Cadastrando…" : "Cadastrar usuário"}</Button>
    </form>}
  </div>;
}
