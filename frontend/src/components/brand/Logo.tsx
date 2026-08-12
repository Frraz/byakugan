/**
 * Marca do Byakugan — olho de cyber intelligence (vetor, escalável).
 * Inspirado em "Byakugan logo.png". Íris pálida com glow lavanda, radar e
 * traços de circuito. Usa `currentColor` no contorno para versão monocromática.
 */

type EyeMarkProps = {
  size?: number;
  className?: string;
  glow?: boolean;
};

export function EyeMark({ size = 40, className, glow = true }: EyeMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      role="img"
      aria-label="Byakugan"
      className={className}
    >
      <defs>
        <radialGradient id="byk-iris" cx="50%" cy="45%" r="55%">
          <stop offset="0%" stopColor="#EAF6FF" />
          <stop offset="45%" stopColor="#C8B6FF" />
          <stop offset="100%" stopColor="#4B3B7A" />
        </radialGradient>
        {glow && (
          <filter id="byk-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2.2" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        )}
      </defs>

      <g filter={glow ? "url(#byk-glow)" : undefined}>
        {/* Contorno amendoado do olho */}
        <path
          d="M6 50 C 26 20, 74 20, 94 50 C 74 80, 26 80, 6 50 Z"
          stroke="currentColor"
          strokeWidth="3"
          fill="none"
        />
        {/* Íris */}
        <circle cx="50" cy="50" r="24" fill="url(#byk-iris)" opacity="0.95" />
        {/* Pupila / radar */}
        <circle cx="50" cy="50" r="12" fill="#0B1220" />
        <circle cx="50" cy="50" r="12" stroke="#00D4FF" strokeWidth="1" opacity="0.7" fill="none" />
        <circle cx="50" cy="50" r="7" stroke="#00D4FF" strokeWidth="0.8" opacity="0.5" fill="none" />
        <line x1="50" y1="50" x2="60" y2="42" stroke="#00D4FF" strokeWidth="1.4" opacity="0.9" />
        {/* Traços de circuito laterais */}
        <g stroke="currentColor" strokeWidth="1.4" opacity="0.85" strokeLinecap="round">
          <path d="M14 50 h10 l4 -4" fill="none" />
          <path d="M86 50 h-10 l-4 4" fill="none" />
          <path d="M22 62 h8" fill="none" />
          <path d="M78 38 h-8" fill="none" />
        </g>
        <circle cx="28" cy="46" r="1.6" fill="#00D4FF" />
        <circle cx="72" cy="54" r="1.6" fill="#00D4FF" />
      </g>
    </svg>
  );
}

type LogoProps = {
  size?: number;
  subtitle?: boolean;
  className?: string;
};

/** Logo horizontal: marca + wordmark. */
export function Logo({ size = 36, subtitle = true, className }: LogoProps) {
  return (
    <div className={`flex items-center gap-3 ${className ?? ""}`}>
      <EyeMark size={size} className="text-accent" />
      <div className="leading-none">
        <span className="block text-lg font-extrabold tracking-[0.2em] text-foreground">
          BYAKUGAN
        </span>
        {subtitle && (
          <span className="block text-[10px] font-semibold tracking-[0.32em] text-primary">
            CYBERSECURITY PLATFORM
          </span>
        )}
      </div>
    </div>
  );
}
