---
name: mcp-server-tools
description: >
  Adding, removing or changing a tool on RedAmon's INBOUND MCP server, where external
  agents connect in with a personal access token. The wiki API reference is generated
  from the server's live tools/list and goes stale silently, and each tool's annotations
  and declared scopes are published to connected clients.
  Trigger: editing a registerTool call in webapp/src/lib/mcp/server.ts; editing tools.ts,
  writeTools.ts, scopeCopy.ts or apiReference.ts in webapp/src/lib/mcp/; changing the
  scope list, default scopes, expiry presets or token prefix in webapp/src/lib/mcpAuth.ts.
license: MIT
metadata:
  author: redamon
  version: "1.0.0"
  scope: [webapp]
  auto_invoke:
    - "Adding, removing or changing a tool on the inbound MCP server"
    - "Changing MCP token scopes, their UI wording, or the MCP API reference generator"
---

## When to Use

- Adding, removing or renaming an inbound MCP tool, or changing its description,
  arguments, annotations or scopes.
- Changing a token scope, its label or blurb, the expiry presets or the token prefix.

For a tool RedAmon's OWN agent calls (outbound, `mcp/servers/`), use
`agentic-tool-integration`. For making a recon setting writable over MCP, use
`project-settings-cascade`. The tools that exist are listed by the server itself and by
the generated reference page, never by this skill.

---

## Critical Rules

- **ALWAYS run `npm run docs:mcp` in `webapp/` after any change this skill's trigger
  names, and commit `MCP-API-Reference.md` inside the `redamon.wiki` repo.** A main-repo
  commit moves only the submodule pointer. The page is rendered by
  [apiReference.ts](../../webapp/src/lib/mcp/apiReference.ts); a hand edit is overwritten
  by the next run.
- **NEVER set `destructiveHint: false` on a tool that overwrites or aborts existing
  state.** In the MCP spec `false` means only additive updates, and clients use it to
  decide when to ask the user first. No test checks this.
- **ALWAYS add an `EXAMPLE_EXTRA_ARGS` entry in
  [apiReference.ts](../../webapp/src/lib/mcp/apiReference.ts) when a tool's body requires
  an argument its JSON Schema marks optional.** The generated example sends only
  schema-required arguments, and the test calls every example.

---

## Pattern: registering a tool

Copy the shape of an existing `registerTool` call in
[server.ts](../../webapp/src/lib/mcp/server.ts): `annotations`,
`_meta: scopesMeta({ required, conditional })` naming exactly the scopes the tool body
enforces with `requireScope`, and `inputSchema`. A scope that applies only to a
particular argument goes under `conditional`, and the arguments that trigger it need a
`CONDITIONAL_TRIGGERS` entry in
[apiReference.test.ts](../../webapp/src/lib/mcp/apiReference.test.ts).

---

## Commands

```bash
cd webapp
npm run docs:mcp                 # rewrites ../redamon.wiki/MCP-API-Reference.md
npx vitest run src/lib/mcp/      # scope, example-call and stale-page checks

cd ../redamon.wiki
git add MCP-API-Reference.md
git commit -m "docs: regenerate MCP API reference"
```

---

## Resources

- [MCP-Server.md](../../redamon.wiki/MCP-Server.md), section "Regenerating the API reference" - what the page is built from, and the stale-page test
- [README.MCP.SERVER.md](../../docs/readmes/README.MCP.SERVER.md) - security model, settings allowlist, deploy wiring
- Related skills: `agentic-tool-integration`, `project-settings-cascade`, `redamon-testing`
