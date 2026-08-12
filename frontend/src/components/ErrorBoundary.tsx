/** Error boundary global — evita tela branca em erro de render. */

import { Component, type ErrorInfo, type ReactNode } from "react";
import { RotateCcw } from "lucide-react";

import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Byakugan render error:", error, info);
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-6 text-center">
        <div className="glass max-w-md space-y-4 p-8">
          <h1 className="text-lg font-bold text-foreground">Algo deu errado</h1>
          <p className="text-sm text-muted-foreground">
            A interface encontrou um erro inesperado. Recarregar costuma resolver.
          </p>
          <Button onClick={() => window.location.reload()}>
            <RotateCcw className="h-4 w-4" />
            Recarregar
          </Button>
        </div>
      </div>
    );
  }
}
