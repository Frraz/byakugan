import { z } from "zod";

/** Validação de formato; autorização e escopo são sempre revalidados pela API. */
export function isTargetValue(value: string): boolean {
  const candidate = value.trim();
  const [address, prefix, ...extra] = candidate.split("/");
  if (extra.length) return false;
  const ipv4 = z.ipv4().safeParse(address).success;
  const ipv6 = z.ipv6().safeParse(address).success;
  if (prefix !== undefined) return (ipv4 || ipv6) && /^\d+$/.test(prefix) && Number(prefix) <= (ipv6 ? 128 : 32);
  return ipv4 || ipv6 || (candidate.length <= 253 && candidate.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)));
}

export const targetValueSchema = z.string().trim().refine(isTargetValue, "Informe um host, domínio, IPv4, IPv6 ou CIDR válido, sem protocolo ou caminho.");
export const targetFormSchema = z.object({
  name: z.string().trim().min(1, "Informe o nome do alvo.").max(255, "Use até 255 caracteres."),
  value: targetValueSchema,
  authorization_scope: z.string(),
  authorization_expires_at: z.string().refine((value) => !value || !Number.isNaN(new Date(value).getTime()), "Informe uma data válida."),
  is_active: z.boolean(),
});
export type TargetFormValues = z.infer<typeof targetFormSchema>;

export const loginSchema = z.object({
  email: z.email("Informe um e-mail válido."),
  password: z.string().min(1, "Informe sua senha."),
});

export const registerSchema = z.object({
  email: z.email("Informe um e-mail válido."),
  password: z.string().min(12, "Use pelo menos 12 caracteres."),
  role: z.enum(["admin", "analyst", "viewer"]),
});

export const knowledgeFormSchema = z.object({
  title: z.string().trim().min(1, "Informe o título.").max(255, "Use até 255 caracteres."),
  slug: z.string().trim().min(1, "Informe o slug.").regex(/^[a-z0-9_-]+$/, "Use letras minúsculas, números, hífen ou sublinhado."),
  category: z.string().min(1, "Selecione a categoria."),
  summary: z.string().trim().min(1, "Informe o resumo."),
  impact: z.string().trim().min(1, "Informe o impacto."),
  stepsText: z.string().trim().min(1, "Informe pelo menos um passo de remediação."),
  refsText: z.string().refine((value) => value.split("\n").map((line) => line.trim()).filter(Boolean).every((line) => {
    try { return ["https:", "http:"].includes(new URL(line).protocol); } catch { return false; }
  }), "Use uma URL HTTP ou HTTPS válida por linha."),
});
