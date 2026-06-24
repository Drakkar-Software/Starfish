/**
 * Copies package README.md files into website/generated/packages/ so
 * Docusaurus can serve them as a second docs plugin instance.
 *
 * Run automatically via prestart / prebuild npm hooks.
 * Output is gitignored (website/.gitignore → /generated).
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const generatedRoot = join(__dirname, "..", "generated", "packages");

const GROUPS = [
  {
    srcDir: join(repoRoot, "packages", "ts"),
    destDir: join(generatedRoot, "typescript"),
    categoryLabel: "TypeScript",
    langSuffix: "TypeScript",
  },
  {
    srcDir: join(repoRoot, "packages", "python"),
    destDir: join(generatedRoot, "python"),
    categoryLabel: "Python",
    langSuffix: "Python",
  },
];

for (const { srcDir, destDir, categoryLabel, langSuffix } of GROUPS) {
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

    writeFileSync(join(destDir, `${pkg}.md`), frontmatter + raw);
    console.log(`  ${langSuffix}: ${pkg}`);
  }
}

console.log("✔ Package READMEs synced to generated/packages/");
