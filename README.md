# github-core-clone-01

[![make.fun](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/ryukiheun/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/ryukiheun/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01)

A standalone GitHub-compatible git forge, built for the [make.fun bounty](https://make.fun/bounty/github-core-clone-01). One process, no UI, no git binary, no external service, no dependencies — only the Node standard library. It serves its own store over four surfaces:

- **git smart HTTP** — upload-pack protocol v2 (`ls-refs`, `fetch` with shallow/deepen) and receive-pack v0 (`report-status`, `side-band-64k`, `delete-refs`), with a packfile reader/writer (plain objects, OFS/REF delta resolution on read)
- **REST v3** under `/api/v3` — repositories, branches, commits, contents, labels, issues, comments, pull requests, files and squash merges
- **GraphQL v4** at `/api/graphql` — the documents `gh` and `github-mcp-server` send, including introspection, cursor pagination and batched operations
- **MCP** at `/mcp` — JSON-RPC 2.0 over streamable HTTP, revision 2026-07-28 (`server/discover`) with the legacy `initialize` handshake, six tools acting on the same store as REST

## Run it

```sh
node --experimental-strip-types main.ts
```

The platform runs `node /bot/main.ts` on Node 22.18 or later. There is nothing to install.

The lifecycle: bind an ephemeral port, `POST $MAKEFUN_ENV_URL/register {"port": N}`, then poll `GET $MAKEFUN_ENV_URL/done` until `{"done": true}` and exit 0. The suite presents `Authorization: Bearer $MAKEFUN_SHOP_TOKEN` on every API call; `/healthz` takes none.

## Layout

- `main.ts` — the entry lifecycle (bind, register, wait for done)
- `app.ts` — the whole forge: object store, git protocol, REST, GraphQL and MCP
- `package.json`, `tsconfig.json`, `LICENSE` (MIT)

## Design

Boring on purpose: an in-memory store (maps keyed by owner/name, oid and number), deterministic timestamps from a counter (no wall clock in any served data), plain-object packs, and a pack cache keyed by repository tip so the 50 concurrent shallow clones serve bytes built once. Nothing is kept on disk; the process holds all state and the suite drives it.
