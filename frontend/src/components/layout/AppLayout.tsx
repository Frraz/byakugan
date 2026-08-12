/** Shell da aplicação: Sidebar fixa + Topbar + área de conteúdo (docs/ui.md). */

import type { ReactNode } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { useAuthStore } from "../../store/auth";
import { useThemeStore } from "../../store/theme";
import { useLogout } from "../../hooks/useAuth";
import { EyeMark, Logo } from "../brand/Logo";
import {
  AssetsIcon,
  DashboardIcon,
  KnowledgeIcon,
  LogoutIcon,
  MoonIcon,
  ReportsIcon,
  ScansIcon,
  SunIcon,
  TargetsIcon,
  VulnIcon,
} from "../icons";

const NAV = [
  { to: "/", label: "Dashboard", icon: DashboardIcon, end: true },
  { to: "/targets", label: "Targets", icon: TargetsIcon },
  { to: "/scans", label: "Scans", icon: ScansIcon },
  { to: "/assets", label: "Assets", icon: AssetsIcon },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: VulnIcon },
  { to: "/reports", label: "Reports", icon: ReportsIcon },
  { to: "/knowledge", label: "Knowledge Base", icon: KnowledgeIcon },
];

function NavItem({ to, label, icon: Icon, end }: (typeof NAV)[number]) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        [
          "flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition",
          isActive
            ? "bg-primary/10 text-primary shadow-glow"
            : "text-muted hover:bg-white/5 hover:text-foreground",
        ].join(" ")
      }
    >
      <Icon aria-hidden />
      {label}
    </NavLink>
  );
}

export function AppLayout({ children }: { children?: ReactNode }) {
  const user = useAuthStore((s) => s.user);
  const { theme, toggle } = useThemeStore();
  const navigate = useNavigate();
  const logout = useLogout();

  const onLogout = () => logout.mutate(undefined, { onSettled: () => navigate("/login") });

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="hidden w-64 shrink-0 flex-col border-r border-border/60 bg-surface-2/40 p-4 backdrop-blur-sm md:flex">
        <Logo size={45} className="px-1 py-2" />
        <nav className="mt-6 flex flex-1 flex-col gap-1">
          {NAV.map((item) => (
            <NavItem key={item.to} {...item} />
          ))}
        </nav>
        <p className="px-2 text-[10px] leading-relaxed text-muted">
          Uso autorizado apenas · protótipo acadêmico
        </p>
      </aside>

      {/* Conteúdo */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-border/60 bg-surface-2/30 px-6 py-3 backdrop-blur-sm">
          <div className="flex items-center gap-2 md:hidden">
            <EyeMark size={24} className="text-accent" />
            <span className="font-bold tracking-widest">BYAKUGAN</span>
          </div>
          <p className="hidden text-sm text-muted md:block">See Everything. Detect Everything.</p>

          <div className="flex items-center gap-3">
            <button
              onClick={toggle}
              className="rounded-lg p-2 text-muted hover:bg-white/5 hover:text-foreground"
              aria-label="Alternar tema"
            >
              {theme === "dark" ? <SunIcon /> : <MoonIcon />}
            </button>
            {user && (
              <div className="text-right">
                <p className="text-sm font-medium text-foreground">{user.email}</p>
                <p className="text-[10px] uppercase tracking-wide text-primary">{user.role}</p>
              </div>
            )}
            <button
              onClick={onLogout}
              className="rounded-lg p-2 text-muted hover:bg-white/5 hover:text-danger"
              aria-label="Sair"
            >
              <LogoutIcon />
            </button>
          </div>
        </header>

        <main className="thin-scroll flex-1 overflow-y-auto p-6">{children ?? <Outlet />}</main>
      </div>
    </div>
  );
}
