import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { laboratory, target, scan, paginated } from "./fixtures";

const routes = ["/", "/targets", "/assets", "/scans", "/scans/scan-1", "/assets/asset-1", "/vulnerabilities", "/evidence", "/reports", "/knowledge-base", "/audit-log", "/account", "/users/new", "/missing-page"];
const sizes = [[1440, 900], [1280, 800], [1024, 768], [768, 1024], [390, 844], [360, 800]];

for (const theme of ["dark", "light"] as const) {
  for (const [width, height] of sizes) {
    test(`${theme} ${width}x${height}: routes fit the viewport`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height });
      await laboratory(page, { theme });
      const errors: string[] = [];
      page.on("pageerror", (error) => errors.push(error.message));
      for (const path of routes) {
        await page.goto(path);
        await expect(page.locator("h1")).toBeVisible();
        await expect(page.getByRole("status").filter({ hasText: "Carregando" })).toHaveCount(0);
        await page.evaluate(() => document.fonts.ready);
        await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth), { message: `${path} overflows at ${width}` }).toBeLessThanOrEqual(1);
        if (["/", "/targets", "/assets", "/scans", "/reports"].includes(path)) await page.screenshot({ path: testInfo.outputPath(`${path.replaceAll("/", "") || "overview"}.png`), fullPage: true });
        if (width === 1440) {
          const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
          expect(result.violations, `${path}: ${JSON.stringify(result.violations.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => ({ target: n.target, summary: n.failureSummary })) })))}`).toEqual([]);
        }
      }
      expect(errors).toEqual([]);
    });
  }
}

for (const state of ["empty", "error"] as const) {
  test(`${state}: list screens have honest states`, async ({ page }) => {
    await laboratory(page, { state });
    for (const path of ["/", "/targets", "/assets", "/scans", "/vulnerabilities", "/evidence", "/reports", "/knowledge-base", "/audit-log"]) {
      await page.goto(path);
      await expect(page.locator("h1")).toBeVisible();
      if (state === "error") await expect(page.getByRole("alert").first()).toBeVisible();
      else await expect(page.locator("main")).toContainText(/Nenhum|Sem dados|ainda não avaliado/i);
    }
  });
}

test("mobile dialogs, keyboard, command search and persistent filters", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 800 });
  await laboratory(page);
  await page.goto("/targets");
  await page.getByRole("button", { name: "Novo alvo", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await page.getByRole("button", { name: "Cadastrar alvo", exact: true }).click();
  await expect(page.getByText("Informe o nome do alvo.")).toBeVisible();
  await expect(page.getByLabel("Nome", { exact: true })).toBeFocused();
  const box = await dialog.boundingBox();
  expect(box!.x).toBeGreaterThanOrEqual(0);
  expect(box!.x + box!.width).toBeLessThanOrEqual(360);
  await page.keyboard.press("Escape");
  const input = page.getByRole("textbox", { name: "Buscar por nome ou valor" });
  await input.fill(target.value);
  await expect(page).toHaveURL(/search=/);
  await page.getByRole("button", { name: "Buscar e navegar (Control K)" }).click();
  await page.getByRole("textbox", { name: "Buscar alvos, scans e artigos" }).fill("laboratorio");
  await page.getByRole("button", { name: new RegExp("Scan.*Laboratório autorizado") }).click();
  await expect(page).toHaveURL(/scans\/scan-1/);
  await page.goBack();
  await expect(input).toHaveValue(target.value);
});

test("viewer sees read actions and cannot access admin forms", async ({ page }) => {
  await laboratory(page, { role: "viewer" });
  await page.goto("/scans");
  await expect(page.getByRole("button", { name: "Novo scan", exact: true })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Auditoria" })).toHaveCount(0);
  await page.goto("/users/new");
  await expect(page.getByRole("alert")).toContainText("Acesso restrito");
  await expect(page.getByLabel("Senha inicial")).toHaveCount(0);
});

test("scan creation displays scope, expiration and controlled impact", async ({ page }) => {
  await laboratory(page);
  await page.goto("/scans?new=1");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("combobox", { name: "Alvo cadastrado" }).click();
  await page.getByRole("option", { name: /Laboratório autorizado/ }).click();
  await expect(page.getByRole("dialog")).toContainText(target.authorization_scope);
  await expect(page.getByRole("button", { name: /Provar impacto/ })).toBeDisabled();
  await page.getByRole("button", { name: /Aggressive/ }).click();
  await expect(page.getByRole("button", { name: /Provar impacto/ })).toBeEnabled();
});

test("report generation and JSON preview at 200 percent layout scale", async ({ page }) => {
  await laboratory(page);
  // 1440 CSS px at 200% zoom provides approximately a 720px layout viewport.
  await page.setViewportSize({ width: 720, height: 450 });
  await page.goto("/reports");
  await page.getByRole("button", { name: "Visualizar" }).click();
  await expect(page.getByRole("dialog")).toContainText("laboratory-only");
  await expect(page.getByRole("button", { name: "Baixar", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Gerar relatório", exact: true }).click();
  await page.getByRole("combobox", { name: "Scan concluído" }).click();
  await page.getByRole("option", { name: /laboratorio.example.test/ }).click();
  await page.getByRole("combobox", { name: "Formato", exact: true }).click();
  await page.getByRole("option", { name: "JSON", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Gerar relatório", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

for (const theme of ["dark", "light"] as const) {
  test(`${theme}: modal focus, investigation tabs and component catalog`, async ({ page }) => {
    await laboratory(page, { theme });
    for (const [path, action] of [["/targets", "Novo alvo"], ["/reports", "Gerar relatório"], ["/scans", "Novo scan"], ["/knowledge-base", "Novo artigo"]]) {
      await page.goto(path);
      const trigger = page.getByRole("button", { name: action, exact: true });
      await trigger.click();
      await expect(page.getByRole("dialog")).toBeVisible();
      const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
      expect(result.violations.map((violation) => ({ id: violation.id, nodes: violation.nodes.map((node) => node.target) }))).toEqual([]);
      await page.keyboard.press("Escape");
      await expect(trigger).toBeFocused();
    }
    await page.goto("/scans/scan-1");
    for (const name of [/Serviços/, /Evidências/, /OWASP/, /Autorização/]) {
      await page.getByRole("tab", { name }).click();
      expect((await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze()).violations).toEqual([]);
    }
    await page.goto("/design-system");
    await expect(page.getByRole("heading", { name: "Sistema visual", exact: true })).toBeVisible();
    expect((await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa"]).analyze()).violations).toEqual([]);
  });
}

test("expired authorization blocks creation; live scan exposes actual progress and cancellation", async ({ page }) => {
  await laboratory(page);
  await page.route(/\/api\/targets\/\?/, (route) => route.fulfill({ json: paginated([{ ...target, authorization_expires_at: "2020-01-01T00:00:00Z" }]) }));
  await page.goto("/scans?new=1");
  await page.getByRole("combobox", { name: "Alvo cadastrado" }).click();
  await page.getByRole("option", { name: /Laboratório autorizado/ }).click();
  await expect(page.getByRole("dialog")).toContainText(/expirada/i);
  await expect(page.getByRole("button", { name: "Autorização expirada", exact: true })).toBeDisabled();
  await page.keyboard.press("Escape");
  await page.route(/\/api\/scans\/scan-1\/$/, (route) => route.fulfill({ json: { ...scan, status: "running", progress: 37, phase: "Descoberta de serviços" } }));
  await page.goto("/scans/scan-1");
  await expect(page.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "37");
  await page.getByRole("button", { name: "Cancelar", exact: true }).click();
  await expect(page.getByRole("alertdialog")).toContainText(/cooperativo/i);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("button", { name: "Cancelar", exact: true })).toBeFocused();
});
