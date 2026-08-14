/** Shell da aplicação: Sidebar fixa + Topbar + área de conteúdo (docs/ui.md). */

import { useState, type ComponentType, type ReactNode } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Boxes,
  Crosshair,
  FileBarChart,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Radar,
  ShieldAlert,
  Sun,
  Target as TargetIcon,
  BookOpen,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useLogout } from "@/hooks/useAuth";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/store/auth";
import { useThemeStore } from "@/store/theme";
import { EyeMark, Logo } from "../brand/Logo";

interface NavEntry {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string }>;
  end?: boolean;
}

const NAV: NavEntry[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/targets", label: "Targets", icon: TargetIcon },
  { to: "/scans", label: "Scans", icon: Radar },
  { to: "/assets", label: "Assets", icon: Boxes },
  { to: "/vulnerabilities", label: "Vulnerabilidades", icon: ShieldAlert },
  { to: "/evidence", label: "Evidências", icon: Crosshair },
  { to: "/reports", label: "Relatórios", icon: FileBarChart },
  { to: "/knowledge", label: "Knowledge Base", icon: BookOpen },
];

function NavItem({ to, label, icon: Icon, end, onNavigate }: NavEntry & { onNavigate?: () => void }) {
  return (
    <NavLink
      to={to}
      end={end}
      onClick={onNavigate}
      className={({ isActive }) =>
        cn(
          "flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition-colors",
          isActive
            ? "bg-primary/10 text-primary shadow-glow"
            : "text-muted-foreground hover:bg-secondary hover:text-foreground",
        )
      }
    >
      <Icon className="h-4 w-4 shrink-0" />
      {label}
    </NavLink>
  );
}

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <>
      <Logo size={45} className="px-1 py-2" />
      <nav className="mt-6 flex flex-1 flex-col gap-1">
        {NAV.map((item) => (
          <NavItem key={item.to} {...item} onNavigate={onNavigate} />
        ))}
      </nav>
      <p className="px-2 text-[10px] leading-relaxed text-muted-foreground">
        Uso autorizado apenas · protótipo acadêmico
      </p>
    </>
  );
}

export function AppLayout({ children }: { children?: ReactNode }) {
  const user = useAuthStore((s) => s.user);
  const { theme, toggle } = useThemeStore();
  const navigate = useNavigate();
  const logout = useLogout();
  const [mobileOpen, setMobileOpen] = useState(false);

  const onLogout = () => logout.mutate(undefined, { onSettled: () => navigate("/login") });

  return (
    <TooltipProvider delayDuration={300}>
      <div className="flex min-h-screen">
        {/* Sidebar desktop */}
        <aside className="hidden w-64 shrink-0 flex-col border-r border-border bg-popover/40 p-4 backdrop-blur-sm md:flex">
          <SidebarContent />
        </aside>

        {/* Conteúdo */}
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 flex items-center justify-between border-b border-border bg-popover/60 px-4 py-3 backdrop-blur-md md:px-6">
            <div className="flex items-center gap-2">
              {/* Menu mobile */}
              <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
                <SheetTrigger asChild>
                  <Button variant="ghost" size="icon" className="md:hidden" aria-label="Abrir menu">
                    <Menu className="h-5 w-5" />
                  </Button>
                </SheetTrigger>
                <SheetContent side="left" className="flex w-72 flex-col p-4">
                  <SheetTitle className="sr-only">Navegação</SheetTitle>
                  <SidebarContent onNavigate={() => setMobileOpen(false)} />
                </SheetContent>
              </Sheet>

              <div className="flex items-center gap-2 md:hidden">
                <EyeMark size={22} className="text-accent" />
                <span className="font-bold tracking-widest">BYAKUGAN</span>
              </div>
              <p className="hidden text-sm text-muted-foreground lg:block">
                See Everything. Detect Everything.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="icon" onClick={toggle} aria-label="Alternar tema">
                    {theme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Tema {theme === "dark" ? "claro" : "escuro"}</TooltipContent>
              </Tooltip>

              {user && (
                <div className="hidden text-right sm:block">
                  <p className="max-w-[180px] truncate text-sm font-medium text-foreground">
                    {user.email}
                  </p>
                  <p className="text-[10px] uppercase tracking-wide text-primary">{user.role}</p>
                </div>
              )}

              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={onLogout}
                    aria-label="Sair"
                    className="hover:text-destructive"
                  >
                    <LogOut className="h-5 w-5" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Sair</TooltipContent>
              </Tooltip>
            </div>
          </header>

          <main className="thin-scroll flex-1 overflow-y-auto p-4 md:p-6">
            <div className="mx-auto max-w-7xl">{children ?? <Outlet />}</div>
          </main>
        </div>
      </div>
    </TooltipProvider>
  );
}
