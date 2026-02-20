import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";

const yaraLanguage = {
  name: "yara",
  displayName: "YARA",
  scopeName: "source.yara",
  aliases: ["yar", "yara-x", "yarax"],
  patterns: [
    { include: "#comments" },
    { include: "#strings" },
    { include: "#numbers" },
    { include: "#keywords" },
    { include: "#meta" },
  ],
  repository: {
    comments: {
      patterns: [
        { name: "comment.line.number-sign.yara", match: "//.*$" },
        { name: "comment.block.yara", begin: "/\\*", end: "\\*/" },
      ],
    },
    strings: {
      patterns: [
        { name: "string.quoted.double.yara", begin: '"', end: '"' },
        { name: "string.quoted.single.yara", begin: "'", end: "'" },
        { name: "string.regex.yara", begin: "/", end: "/[a-zA-Z]*" },
      ],
    },
    numbers: {
      patterns: [{ name: "constant.numeric.yara", match: "\\b\\d+\\b" }],
    },
    keywords: {
      patterns: [
        {
          name: "keyword.control.yara",
          match:
            "\\b(rule|meta|strings|condition|import|private|global|and|or|not|any|all|of|them|for|in|at|entrypoint|filesize|true|false)\\b",
        },
      ],
    },
    meta: {
      patterns: [
        { name: "entity.name.type.rule.yara", match: "\\brule\\s+[A-Za-z_][A-Za-z0-9_]*\\b" },
        { name: "variable.other.match-id.yara", match: "\\$[A-Za-z_][A-Za-z0-9_]*" },
      ],
    },
  },
};

export default withMermaid(
  defineConfig({
    title: "Cisco Skill Scanner",
    description:
      "Security scanner for AI Agent Skills — detects prompt injection, data exfiltration, and malicious code patterns",

    base: "/skill-scanner/",

    head: [
      [
        "link",
        {
          rel: "icon",
          type: "image/svg+xml",
          href: "/skill-scanner/favicon.svg",
        },
      ],
    ],

    themeConfig: {
      logo: "/logo.svg",

      nav: [
        { text: "Home", link: "/" },
        { text: "Features", link: "/features/" },
        { text: "User Guide", link: "/user-guide/" },
        { text: "Architecture", link: "/architecture/" },
        { text: "Reference", link: "/reference/" },
        {
          text: "Links",
          items: [
            {
              text: "PyPI",
              link: "https://pypi.org/project/cisco-ai-skill-scanner/",
            },
            {
              text: "Discord",
              link: "https://discord.com/invite/nKWtDcXxtx",
            },
            {
              text: "Cisco AI Defense",
              link: "https://www.cisco.com/site/us/en/products/security/ai-defense/index.html",
            },
          ],
        },
      ],

      sidebar: [
        {
          text: "Features",
          items: [{ text: "Feature Overview", link: "/features/" }],
        },
        {
          text: "Concepts",
          items: [
            { text: "Security Model", link: "/concepts/security-model" },
            { text: "Remote Skills Model", link: "/concepts/remote-skills-analysis" },
          ],
        },
        {
          text: "Getting Started",
          items: [
            { text: "Quick Start", link: "/getting-started/quick-start" },
          ],
        },
        {
          text: "User Guide",
          items: [
            { text: "Overview", link: "/user-guide/" },
            {
              text: "Installation and Configuration",
              link: "/user-guide/installation-and-configuration",
            },
            { text: "CLI Usage", link: "/user-guide/cli-usage" },
            { text: "Python SDK", link: "/user-guide/python-sdk" },
            { text: "API Server", link: "/user-guide/api-server" },
            { text: "API Endpoints Detail", link: "/user-guide/api-endpoints-detail" },
            { text: "API Operations", link: "/user-guide/api-operations" },
            { text: "API Rationale", link: "/user-guide/api-rationale" },
            {
              text: "Scan Policies Overview",
              link: "/user-guide/scan-policies-overview",
            },
            {
              text: "Custom Policy Configuration",
              link: "/user-guide/custom-policy-configuration",
            },
          ],
        },
        {
          text: "Architecture",
          items: [
            { text: "Overview", link: "/architecture/" },
            { text: "Scanning Pipeline", link: "/architecture/scanning-pipeline" },
            { text: "Threat Taxonomy", link: "/architecture/threat-taxonomy" },
            { text: "Binary Handling", link: "/architecture/binary-handling" },
          ],
        },
        {
          text: "Analyzers",
          items: [
            { text: "Overview", link: "/architecture/analyzers/" },
            { text: "Static Analyzer", link: "/architecture/analyzers/static-analyzer" },
            {
              text: "Behavioral Analyzer",
              link: "/architecture/analyzers/behavioral-analyzer",
            },
            { text: "LLM Analyzer", link: "/architecture/analyzers/llm-analyzer" },
            { text: "Meta-Analyzer", link: "/architecture/analyzers/meta-analyzer" },
            { text: "AI Defense Analyzer", link: "/architecture/analyzers/aidefense-analyzer" },
            {
              text: "Analyzer Selection Guide",
              link: "/architecture/analyzers/meta-and-external-analyzers",
            },
            {
              text: "Writing Custom Rules",
              link: "/architecture/analyzers/writing-custom-rules",
            },
          ],
        },
        {
          text: "Development",
          items: [
            { text: "Overview", link: "/development/" },
            { text: "Setup and Testing", link: "/development/setup-and-testing" },
            { text: "CI/CD & Integrations", link: "/development/integrations" },
            { text: "Examples and How-To", link: "/guides/examples-and-how-to" },
          ],
        },
        {
          text: "Reference",
          items: [
            { text: "Overview", link: "/reference/" },
            { text: "Configuration Reference", link: "/reference/configuration-reference" },
            { text: "API Endpoint Reference", link: "/reference/api-endpoint-reference" },
            { text: "Output Formats", link: "/reference/output-formats" },
            { text: "Policy Quick Reference", link: "/reference/policy-quick-reference" },
            {
              text: "Dependencies and LLM Providers",
              link: "/reference/dependencies-and-llm-providers",
            },
            { text: "CLI Command Reference", link: "/reference/cli-command-reference" },
          ],
        },
      ],

      socialLinks: [
        {
          icon: "github",
          link: "https://github.com/cisco-ai-defense/skill-scanner",
        },
        {
          icon: "discord",
          link: "https://discord.com/invite/nKWtDcXxtx",
        },
      ],

      search: {
        provider: "local",
      },
      lastUpdated: {
        text: "Last updated",
      },

      editLink: {
        pattern:
          "https://github.com/cisco-ai-defense/skill-scanner/edit/main/docs/:path",
        text: "Edit this page on GitHub",
      },

      footer: {
        message:
          'Released under the <a href="https://github.com/cisco-ai-defense/skill-scanner/blob/main/LICENSE">Apache 2.0 License</a>.',
        copyright: "Copyright © 2026 Cisco Systems, Inc. and its affiliates",
      },
    },

    ignoreDeadLinks: [/TESTING/, /README/],

    mermaid: {},
    mermaidPlugin: {
      class: "mermaid",
    },

    markdown: {
      languages: [yaraLanguage],
      lineNumbers: true,
    },
  })
);
