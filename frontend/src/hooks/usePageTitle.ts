/** Define o título do documento (aba do navegador) para a página atual. */

import { useEffect } from "react";

export function usePageTitle(title: string): void {
  useEffect(() => {
    const previous = document.title;
    document.title = `${title} · Byakugan`;
    return () => {
      document.title = previous;
    };
  }, [title]);
}
