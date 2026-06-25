/**
 * Copies package README.md files into website/generated/packages/ so
 * Docusaurus can serve them as a second docs plugin instance.
 *
 * Also rewrites links inside the copied content so they resolve correctly
 * on the site (the relative paths in source READMEs assume the monorepo
 * layout and would be soft-broken once flattened into generated/).
 *
 * Run automatically via prestart / prebuild npm hooks.
 * Output is gitignored (website/.gitignore → /generated).
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, resolve, relative, basename } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const repoDocs = join(repoRoot, "docs");          // old docs root (no longer used at runtime, but kept as resolution base for link map)
const generatedRoot = join(__dirname, "..", "generated", "packages");

// ─── DOCS ROUTE MAP ────────────────────────────────────────────────────────
// Maps old repo-root-docs-relative paths to new Docusaurus site routes.
// Used to rewrite ../../../docs/... links in package READMEs.
// Kept in sync with website/scripts/migrate-docs.mjs MAPPING table.
const DOCS_ROUTE_MAP = {
  "index.md":                              "/",
  // Getting Started
  "ts/client/01-getting-started.md":       "/getting-started/intro",
  "ts/client/README.md":                   "/getting-started/client-overview",
  "ts/client/10-platform-setup.md":        "/getting-started/platform-setup",
  // Client Core
  "ts/client/02-starfish-client.md":       "/client-core/starfish-client",
  "ts/client/03-sync-manager.md":          "/client-core/sync-manager",
  "ts/client/07-conflict-resolution.md":   "/client-core/conflict-resolution",
  "ts/client/15-error-retry.md":           "/client-core/error-retry",
  "ts/client/27-sse-subscribe.md":         "/client-core/sse-subscribe",
  // State & Offline
  "ts/client/05-state-zustand.md":         "/state-offline/state-zustand",
  "ts/client/06-state-legend.md":          "/state-offline/state-legend",
  "ts/client/08-offline-connectivity.md":  "/state-offline/offline-connectivity",
  "ts/client/14-multi-tab-sync.md":        "/state-offline/multi-tab-sync",
  "ts/client/29-kv-pull-cache.md":         "/state-offline/kv-pull-cache",
  // Encryption & Identity
  "ts/client/04-encryption.md":            "/encryption-identity/encryption",
  "ts/client/11-identity-key-derivation.md": "/encryption-identity/identity-key-derivation",
  "ts/client/26-identity-models.md":       "/encryption-identity/identity-models",
  "ts/client/23-multi-recipient-delegated.md": "/encryption-identity/multi-recipient-delegated",
  "ts/client/25-capability-certs.md":      "/encryption-identity/capability-certs",
  "ts/client/24-pairing.md":               "/encryption-identity/pairing",
  "ts/client/28-anonymous-append.md":      "/encryption-identity/anonymous-append",
  // Data Modeling & Collections
  "ts/client/19-collection-patterns.md":   "/data-modeling/collection-patterns",
  "ts/client/20-namespaces.md":            "/data-modeling/namespaces",
  "ts/client/22-binary-collections.md":    "/data-modeling/binary-collections",
  "ts/client/18-multi-document-architecture.md": "/data-modeling/multi-document-architecture",
  "ts/client/12-schema-versioning.md":     "/data-modeling/schema-versioning",
  "ts/client/17-data-export-import.md":    "/data-modeling/data-export-import",
  "ts/client/31-bulk-multi-content-sync.md": "/data-modeling/bulk-multi-content-sync",
  // Integration & Operations
  "ts/client/09-integration-patterns.md":  "/integration-operations/integration-patterns",
  "ts/client/13-testing.md":               "/integration-operations/testing",
  "ts/client/16-logging-observability.md": "/integration-operations/logging-observability",
  "ts/client/30-wal-client-adapters.md":   "/integration-operations/wal-client-adapters",
  // Server
  "ts/server/storage.md":                  "/server/storage",
  "ts/server/config-endpoint.md":          "/server/config-endpoint",
  "ts/server/list-endpoint.md":            "/server/list-endpoint",
  "ts/server/group-access.md":             "/server/group-access",
  "ts/server/identity-restrictions.md":    "/server/identity-restrictions",
  "ts/server/rate-limiting.md":            "/server/rate-limiting",
  "ts/server/append-only-collections.md":  "/server/append-only-collections",
  "ts/server/root-only-collections.md":    "/server/root-only-collections",
  // The missing target referenced by some package READMEs — now resolved:
  "ts/server/entitlements.md":             "/extensions/entitlements",
  // WAL / CRDT
  "ts/wal/01-overview.md":                 "/wal/overview",
  "ts/wal/02-crdt-model.md":              "/wal/crdt-model",
  "ts/wal/03-document.md":               "/wal/document",
  "ts/wal/04-reconcile.md":              "/wal/reconcile",
  "ts/wal/05-snapshots.md":              "/wal/snapshots",
  "ts/wal/06-security.md":               "/wal/security",
  // Sharing / Webhook
  "ts/sharing/01-overview.md":             "/sharing/overview",
  "ts/sharing/02-public-links.md":         "/sharing/public-links",
  "ts/webhook/01-overview.md":             "/webhook/overview",
  "ts/webhook/02-sealed-write.md":         "/webhook/sealed-write",
  // Analytics
  "ts/events/README.md":                   "/analytics/events",
  "python/events/README.md":               "/analytics/events",
  // Extensions
  "ts/protocol/01-overview.md":            "/extensions/protocol",
  "ts/identities/01-overview.md":          "/extensions/identities",
  "ts/keyring/01-overview.md":             "/extensions/keyring",
  "ts/spaces/01-overview.md":              "/extensions/spaces",
  "ts/audit/01-overview.md":               "/extensions/audit",
  "ts/entitlements/01-overview.md":        "/extensions/entitlements",
  "ts/outbox/01-overview.md":              "/extensions/outbox",
  "ts/projection/01-overview.md":          "/extensions/projection",
  "ts/queuing/01-overview.md":             "/extensions/queuing",
  "ts/replica/01-overview.md":             "/extensions/replica",
  // Python / Migration
  "python/server/storage.md":              "/python/server/storage",
  "migration/v2-to-v3.md":                "/migration/v2-to-v3",
};

// Directory-level links (no .md) that point at a known docs subtree
const DOCS_DIR_ROUTE_MAP = {
  "ts/client":  "/getting-started/intro",
  "ts/server":  "/server/storage",
  "ts/wal":     "/wal/overview",
  "ts":         "/getting-started/intro",
  "migration":  "/migration/v2-to-v3",
};

/**
 * Rewrite links in a package README so they resolve correctly on the site.
 * srcFilePath: absolute path to the source README.md (used for relative resolution).
 * pkgLang: 'typescript' or 'python' (for sibling-package route generation)
 */
function rewriteLinks(content, srcFilePath, pkgLang) {
  const srcDir = dirname(srcFilePath);

  return content.replace(/(?<!!)\]\(([^)]+)\)/g, (match, raw) => {
    // Skip external and mailto links
    if (/^https?:\/\//.test(raw) || /^mailto:/i.test(raw)) return match;
    // Skip pure same-page anchors
    if (raw.startsWith("#")) return match;

    // Strip optional link title:  path "Title"  or  path 'Title'
    const rawClean = raw.replace(/\s+["'][^"']*["']$/, "").trim();

    const hashIdx = rawClean.indexOf("#");
    const pathPart = hashIdx >= 0 ? rawClean.slice(0, hashIdx) : rawClean;
    const anchor   = hashIdx >= 0 ? rawClean.slice(hashIdx)    : "";

    // ── tests/test-vectors → GitHub URL ──────────────────────────────────────
    if (pathPart.includes("tests/test-vectors")) {
      const tvMatch = pathPart.match(/tests\/test-vectors\/?(.*?)$/);
      if (tvMatch !== null) {
        const suffix = tvMatch[1];
        if (suffix) {
          // Specific file → blob URL
          return `](https://github.com/Drakkar-Software/Starfish/blob/master/tests/test-vectors/${suffix})`;
        } else {
          // Directory link → tree URL
          return `](https://github.com/Drakkar-Software/Starfish/tree/master/tests/test-vectors/)`;
        }
      }
    }

    // Resolve the link target to an absolute path
    const resolvedAbs = resolve(srcDir, pathPart);

    // ── Root README → site home ───────────────────────────────────────────────
    const relFromRoot = relative(repoRoot, resolvedAbs);
    if (relFromRoot === "README.md") {
      return `](/)`;
    }

    // ── docs/ link (.md file) → site route ──────────────────────────────────
    if (pathPart.endsWith(".md")) {
      const relFromDocs = relative(repoDocs, resolvedAbs).replace(/\\/g, "/");
      if (!relFromDocs.startsWith("..")) {
        const route = DOCS_ROUTE_MAP[relFromDocs];
        if (route) return `](${route}${anchor})`;
      }
    }

    // ── docs/ directory link (no .md) → site route ──────────────────────────
    if (!pathPart.endsWith(".md")) {
      const relFromDocs = relative(repoDocs, resolvedAbs).replace(/\\/g, "/").replace(/\/$/, "");
      if (!relFromDocs.startsWith("..")) {
        const route = DOCS_DIR_ROUTE_MAP[relFromDocs];
        if (route) return `](${route})`;
      }
    }

    // ── Sibling package README (../other-pkg/README.md) → /packages/<lang>/<pkg> ─
    const relFromPackages = relative(join(repoRoot, "packages"), resolvedAbs).replace(/\\/g, "/");
    const pkgMatch = relFromPackages.match(/^(ts|python)\/([^/]+)\/README\.md$/);
    if (pkgMatch) {
      const lang = pkgMatch[1] === "ts" ? "typescript" : "python";
      const pkg  = pkgMatch[2];
      return `](/packages/${lang}/${pkg})`;
    }

    return match; // unchanged — leave as-is
  });
}

// ─── SYNC ──────────────────────────────────────────────────────────────────

const GROUPS = [
  {
    srcDir: join(repoRoot, "packages", "ts"),
    destDir: join(generatedRoot, "typescript"),
    categoryLabel: "TypeScript",
    langSuffix: "TypeScript",
    pkgLang: "typescript",
  },
  {
    srcDir: join(repoRoot, "packages", "python"),
    destDir: join(generatedRoot, "python"),
    categoryLabel: "Python",
    langSuffix: "Python",
    pkgLang: "python",
  },
];

for (const { srcDir, destDir, categoryLabel, langSuffix, pkgLang } of GROUPS) {
  mkdirSync(destDir, { recursive: true });

  // Category label for Docusaurus sidebar
  writeFileSync(
    join(destDir, "_category_.json"),
    JSON.stringify({ label: categoryLabel, collapsible: true, collapsed: false }, null, 2) + "\n",
  );

  const pkgDirs = readdirSync(srcDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

  for (const pkg of pkgDirs) {
    const readmePath = join(srcDir, pkg, "README.md");
    if (!existsSync(readmePath)) continue;

    const raw = readFileSync(readmePath, "utf-8");

    // Extract title from the first # heading
    const titleMatch = raw.match(/^#\s+(.+)$/m);
    const title = titleMatch ? titleMatch[1].trim() : pkg;

    // Rewrite links so they resolve correctly on the Docusaurus site
    const rewritten = rewriteLinks(raw, readmePath, pkgLang);

    // Build frontmatter: title from README h1, sidebar_label from dir name
    const frontmatter = [
      "---",
      `title: "${title.replace(/"/g, '\\"')}"`,
      `sidebar_label: "${pkg}"`,
      `custom_edit_url: https://github.com/Drakkar-Software/Starfish/edit/master/packages/${langSuffix.toLowerCase() === "typescript" ? "ts" : "python"}/${pkg}/README.md`,
      "---",
      "",
      "",
    ].join("\n");

    writeFileSync(join(destDir, `${pkg}.md`), frontmatter + rewritten);
    console.log(`  ${langSuffix}: ${pkg}`);
  }
}

console.log("✔ Package READMEs synced to generated/packages/");
