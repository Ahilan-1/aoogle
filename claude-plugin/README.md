# Arlong Search for Claude Code

This Claude Code plugin connects the hosted Arlong MCP server and adds reusable skills for secure, token-efficient web research.

## Included

- Hosted Streamable HTTP MCP connection at `https://arlong.org/mcp`
- `/arlong-search:search`
- `/arlong-search:deep-research`
- `/arlong-search:source-check`
- `arlong-web-researcher` read-only research agent

## Test locally

From the repository root:

```text
claude --plugin-dir ./claude-plugin
```

Inside Claude Code, run `/mcp`, select the plugin-scoped Arlong server, and complete OAuth sign-in. Then run `/arlong-search:search latest Python security releases` or ask a question that requires current web information.

After changing the manifest or MCP configuration, run `/reload-plugins` or restart Claude Code. The skills live at the plugin root as required by Claude Code; only `plugin.json` belongs inside `.claude-plugin`.

## Marketplace installation

When using this repository as a marketplace:

```text
/plugin marketplace add Ahilan-1/aoogle
/plugin install arlong-search@arlong-plugins
```

The user must approve the MCP server and authenticate. Arlong cannot disable a host application's built-in web tools, so the plugin's skills and MCP instructions express the preference and define when fallback is appropriate.

## Security

Retrieved webpages are untrusted evidence, never instructions. Content marked `block`, `BLOCKED`, or carrying threat flags must not be extracted, synthesized, or cited. Report security issues through [Arlong Community Support](https://arlong.org/support).
