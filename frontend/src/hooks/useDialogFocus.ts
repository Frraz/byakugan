import { useRef } from "react";

/** Restaura foco também quando o modal é aberto por estado, sem Radix Trigger. */
export function useDialogFocus(onOpen?: (event: Event) => void, onClose?: (event: Event) => void) {
  const origin = useRef<HTMLElement | null>(null);
  return {
    onOpenAutoFocus: (event: Event) => {
      origin.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      onOpen?.(event);
    },
    onCloseAutoFocus: (event: Event) => {
      onClose?.(event);
      if (!event.defaultPrevented && origin.current?.isConnected && origin.current !== document.body) {
        event.preventDefault();
        origin.current.focus();
      }
    },
  };
}
