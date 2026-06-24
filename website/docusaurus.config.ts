import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

const config: Config = {
  title: "Starfish",
  tagline: "Generic document sync with hash-based conflict detection, incremental sync, and role-based access control.",
  favicon: "img/favicon.ico",

  future: {
    v4: true,
  },

  url: "https://starfish.drakkar.software",
  baseUrl: "/Starfish/",

  organizationName: "Drakkar-Software",
  projectName: "Starfish",
  trailingSlash: false,

  onBrokenLinks: "throw",
  onBrokenAnchors: "throw",

  // Parse .md files as CommonMark (not MDX) to handle prose tokens like
  // {identity}, <col>, <ts> that appear throughout the docs.
  markdown: {
    format: "detect",
    hooks: {
      // v4 migration: onBrokenMarkdownLinks moved here from top-level.
      onBrokenMarkdownLinks: "warn",
    },
  },

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  plugins: [
    // Second docs instance: package READMEs synced into generated/packages/
    [
      "@docusaurus/plugin-content-docs",
      {
        id: "packages",
        path: "./generated/packages",
        routeBasePath: "packages",
        sidebarPath: "./sidebars-packages.ts",
      },
    ],
  ],

  presets: [
    [
      "classic",
      {
        docs: {
          // Docs now live inside website/docs/ (Docusaurus default location)
          // Serve docs at the site root (no /docs/ prefix)
          routeBasePath: "/",
          sidebarPath: "./sidebars.ts",
          editUrl:
            "https://github.com/Drakkar-Software/Starfish/edit/master/website/docs/",
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: "Starfish",
      items: [
        {
          type: "docSidebar",
          sidebarId: "mainSidebar",
          position: "left",
          label: "Docs",
        },
        {
          type: "docSidebar",
          sidebarId: "packagesSidebar",
          docsPluginId: "packages",
          position: "left",
          label: "Packages",
        },
        {
          href: "https://github.com/Drakkar-Software/Starfish",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            { label: "Getting Started", to: "/getting-started/intro" },
            { label: "Migration v2 → v3", to: "/migration/v2-to-v3" },
          ],
        },
        {
          title: "Packages",
          items: [
            { label: "TypeScript", to: "/packages/typescript/client" },
            { label: "Python", to: "/packages/python/client" },
          ],
        },
        {
          title: "More",
          items: [
            {
              label: "GitHub",
              href: "https://github.com/Drakkar-Software/Starfish",
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Drakkar Software. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["bash", "python", "typescript"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
