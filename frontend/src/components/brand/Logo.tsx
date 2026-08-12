import byakuganEye from "../../assets/byakugan-eye.png";

/**
 * Marca do Byakugan — olho de cyber intelligence (raster, `byakugan-eye.png`).
 * Mantém a proporção original da arte (1204×651).
 */

const EYE_ASPECT_RATIO = 1204 / 651;

type EyeMarkProps = {
  size?: number;
  className?: string;
  glow?: boolean;
};

export function EyeMark({ size = 40, className, glow = true }: EyeMarkProps) {
  return (
    <img
      src={byakuganEye}
      alt="Byakugan"
      width={size}
      height={Math.round(size / EYE_ASPECT_RATIO)}
      className={className}
      style={glow ? { filter: "drop-shadow(0 0 6px rgba(200,182,255,0.55))" } : undefined}
    />
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
