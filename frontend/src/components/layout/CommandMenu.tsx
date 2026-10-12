import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Search } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ErrorBanner } from "@/components/ui/error-banner";
import { useDebounce } from "@/hooks/useDebounce";
import { apiFetch } from "@/lib/api";
import { errorMessage } from "@/lib/errors";
import type { Paginated, Target, Scan, KnowledgeArticle } from "@/lib/types";

const destinations = [
  ["Dashboard", "/"], ["Alvos", "/targets"], ["Scans", "/scans"],
  ["Vulnerabilidades", "/vulnerabilities"], ["Evidências", "/evidence"],
  ["Relatórios", "/reports"], ["Base de conhecimento", "/knowledge-base"], ["Minha conta", "/account"],
];

export function CommandMenu() {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const term = useDebounce(search.trim());
  const navigate = useNavigate();
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((current) => !current);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  const results = useQuery({
    queryKey: ["command-search", term],
    enabled: open && term.length >= 2,
    queryFn: async () => {
      const params = { search: term };
      const responses = await Promise.allSettled([
        apiFetch<Paginated<Target>>("/targets/", { params }),
        apiFetch<Paginated<Scan>>("/scans/", { params }),
        apiFetch<Paginated<KnowledgeArticle>>("/knowledge-base/", { params }),
      ]);
      const [targets, scans, articles] = responses;
      return {
        entries: [
          ...(targets.status === "fulfilled" ? targets.value.results.slice(0, 4).map((t) => ({ label: `${t.name} · ${t.value}`, to: `/targets?search=${encodeURIComponent(t.value)}`, kind: "Alvo" })) : []),
          ...(scans.status === "fulfilled" ? scans.value.results.slice(0, 4).map((s) => ({ label: s.target_name || s.target, to: `/scans/${s.id}`, kind: "Scan" })) : []),
          ...(articles.status === "fulfilled" ? articles.value.results.slice(0, 4).map((a) => ({ label: a.title, to: `/knowledge-base?search=${encodeURIComponent(a.title)}`, kind: "Artigo" })) : []),
        ],
        errors: responses.filter((r) => r.status === "rejected").map((r) => errorMessage(r.reason)),
      };
    },
  });
  const go = (to: string) => { setOpen(false); navigate(to); };
  return (
    <>
      <Button variant="outline" size="sm" aria-label="Buscar e navegar (Control K)" onClick={() => { setSearch(""); setOpen(true); }}>
        <Search className="h-4 w-4" /><span className="hidden sm:inline">Buscar</span><kbd className="hidden text-xs text-muted-foreground lg:inline">Ctrl K</kbd>
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader className="pr-6 text-left">
            <DialogTitle>Buscar e navegar</DialogTitle>
            <DialogDescription>Consulte alvos, scans e artigos. Use Tab para escolher um resultado e Enter para abrir.</DialogDescription>
          </DialogHeader>
          <Input aria-label="Buscar alvos, scans e artigos" placeholder="Digite pelo menos 2 caracteres…" value={search} onChange={(event) => setSearch(event.target.value)} />
          <div className="max-h-[50dvh] space-y-2 overflow-y-auto" aria-live="polite">
            {term.length >= 2 && results.isFetching && <p role="status" className="text-sm text-muted-foreground">Buscando registros…</p>}
            {results.data?.errors.length ? <ErrorBanner message="Parte da busca está indisponível." onRetry={() => void results.refetch()} /> : null}
            {term.length >= 2 && !results.isFetching && results.data?.entries.length === 0 && !results.data.errors.length && <p className="text-sm text-muted-foreground">Nenhum registro encontrado.</p>}
            {term.length >= 2 && results.data?.entries.map((entry) => <button key={entry.to} onClick={() => go(entry.to)} className="flex w-full flex-col rounded-md px-3 py-2 text-left hover:bg-accent"><span className="text-xs text-muted-foreground">{entry.kind}</span><span className="break-all text-sm">{entry.label}</span></button>)}
            <p className="pt-2 text-xs font-medium text-muted-foreground">Navegação</p>
            {destinations.filter(([label]) => label.toLocaleLowerCase().includes(search.toLocaleLowerCase())).map(([label, to]) => <button key={to} onClick={() => go(to)} className="block w-full rounded-md px-3 py-2 text-left text-sm hover:bg-accent">{label}</button>)}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
