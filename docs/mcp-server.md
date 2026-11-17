# Decryptor MCP Server: design spec

Decisions: `docs/adr/0001-*`. Glossary: `CONTEXT.md`. Status: implemented and registered in Hermes; a real decryption against a database is still unverified.

## Shape

- Stdio MCP server; second binary `sql-decryptor-mcp` in `src-tauri`, reusing `engine` (no new crates).
- Runs on Linux (this machine) under Hermes `mcp_servers`.

## Configuration (server environment)

| Variable | Source | Meaning |
|---|---|---|
| `SQL_DECRYPTOR_SERVER` | `~/.hermes/.env` | SQL Server host / `host\instance` |
| `SQL_DECRYPTOR_USER` | `~/.hermes/.env` | SQL login |
| `SQL_DECRYPTOR_PASSWORD` | `~/.hermes/.env` | forwarded only to `sqlcmd` as `SQLCMDPASSWORD` |
| `SQL_DECRYPTOR_DATABASE` | `~/.hermes/.env` | default database |
| `SQL_DECRYPTOR_ALLOW_DBCC_PAGE` | config.yaml | present and truthy (e.g. `enabled`), or `decrypt_procedure` refuses (Risk Acknowledgment); `0`/absent revokes |
| `SQL_DECRYPTOR_MAX_PAGES` | config.yaml | Page Cap, default 32, 1–256; not overridable per call |

Hermes resolves `${VAR}` in a stdio `env` block from `~/.hermes/.env` (docs: `reference/mcp-config-reference.md`, "Environment variable references").

## Tools

| Tool | Arguments | Returns | Annotation |
|---|---|---|---|
| `list_databases` | — | online databases the login can access | `readOnlyHint: true` |
| `list_procedures` | `database?`, `filter?` | `schema.name`, `object_id`, `encrypted` | `readOnlyHint: true` |
| `decrypt_procedure` | `procedure` (`schema.name`), `database?` | raw source text (same 30 B–8 MB check as the GUI) | none, so Hermes prompts |

`database?` defaults to `SQL_DECRYPTOR_DATABASE` and is validated with `check_database_name`. No Export tool; no SQL formatting.

## Hermes registration

Entry `sql_decryptor` with `trust: untrusted`, so every `decrypt_procedure` call goes through Hermes approval (Allow Once / Session / Always). YOLO, `approvals.mode: off`, or an "Always" answer remove that prompt; the config-level allow flag remains.

Registered with `hermes mcp add` plus `hermes config set mcp_servers.sql_decryptor.trust untrusted`; Hermes blocks agents from editing `config.yaml` directly, and its stdio `env` values must be strings (hence `enabled`, not `1`).

## Launch prerequisites

- `sqlcmd` on the server's PATH (present: `~/.local/bin/sqlcmd`; set `PATH` in the entry's `env`).
- The user fills the four `SQL_DECRYPTOR_*` values in `~/.hermes/.env`.
- Restored or DBA-approved database; `DBCC PAGE` permission (sysadmin).

## Out of scope

Export, formatting, DBX integration, Windows build, cross-process lock with the desktop app.
