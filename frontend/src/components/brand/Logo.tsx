/**
 * Marca do Byakugan — ponto focal e dois arcos assimétricos (PLANO_REDESIGN_BYAKUGAN.md, §2.3).
 * Vetor puro (sem raster, sem referência literal a um olho): lê-se como um
 * instrumento de precisão/foco. Funciona em 16–32px (sidebar compacta,
 * favicon) e em tamanhos grandes (login, capa de relatório).
 */

type MarkProps = {
  size?: number;
  className?: string;
};

/** Símbolo isolado: dois arcos (traço, `currentColor`) + ponto focal (acento). */
export function Mark({ size = 32, className }: MarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      className={className}
      role="img"
      aria-label="Byakugan"
    >
      <path
        d="M5 19A13 13 0 0 1 27 13"
        stroke="currentColor"
        strokeWidth="2.25"
        strokeLinecap="round"
      />
      <path
        d="M9 24A9 9 0 0 1 24 21"
        stroke="currentColor"
        strokeWidth="2.25"
        strokeLinecap="round"
        opacity="0.55"
      />
      <circle cx="14" cy="15" r="2.4" className="fill-primary" />
    </svg>
  );
}

type LogoProps = {
  size?: number;
  subtitle?: boolean;
  className?: string;
};

/** Logo horizontal: marca + wordmark. */
export function Logo({ size = 32, subtitle = true, className }: LogoProps) {
  return (
    <div className={`flex items-center gap-2.5 ${className ?? ""}`}>
      <Mark size={size} className="shrink-0 text-foreground" />
      <div className="min-w-0 leading-none">
        <span className="block text-base font-semibold tracking-[0.14em] text-foreground">
          BYAKUGAN
        </span>
        {subtitle && (
          <span className="block whitespace-nowrap text-[9px] font-medium tracking-[0.12em] text-muted-foreground">
            SECURITY ASSESSMENT
          </span>
        )}
      </div>
    </div>
  );
}
