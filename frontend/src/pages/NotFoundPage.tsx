/** Rota inexistente dentro da área autenticada (docs/ui.md §5.12). */

import { Compass } from "lucide-react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/PageHeader";
import { usePageTitle } from "@/hooks/usePageTitle";

export function NotFoundPage() {
  usePageTitle("Página não encontrada");
  return (
    <div>
      <PageHeader title="Página não encontrada" />
      <div className="flex min-h-[60vh] items-center justify-center">
      <EmptyState
        icon={Compass}
        title="Confira o endereço"
        hint="O endereço acessado não existe ou foi movido."
        action={
          <Button asChild>
            <Link to="/">Voltar ao dashboard</Link>
          </Button>
        }
        className="max-w-md"
      />
      </div>
    </div>
  );
}
