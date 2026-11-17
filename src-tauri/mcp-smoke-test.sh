#!/usr/bin/env bash
# Smoke test for the Decryptor MCP server: protocol, tool wiring, and the config gates.
# No database needed. Real decryption still needs a restored database and credentials.
set -euo pipefail
cd "$(dirname "$0")"
BIN=target/release/sql_decryptor_mcp
[ -x "$BIN" ] || { echo "build first: cargo build --release --bin sql_decryptor_mcp"; exit 1; }

# 1. initialize + tools/list, no environment at all.
out=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | env -u SQL_DECRYPTOR_SERVER -u SQL_DECRYPTOR_USER -u SQL_DECRYPTOR_PASSWORD -u SQL_DECRYPTOR_DATABASE "$BIN")

[ "$(printf '%s\n' "$out" | wc -l)" = 2 ] || { echo "FAIL: notifications must not be answered"; printf '%s\n' "$out"; exit 1; }
printf '%s' "$out" | jq -e 'select(.id==1) | .result.serverInfo.name=="sql-decryptor" and .result.capabilities.tools' >/dev/null \
  || { echo "FAIL: initialize"; echo "$out"; exit 1; }
printf '%s' "$out" | jq -e 'select(.id==2) | [.result.tools[].name] == ["list_databases","list_procedures","decrypt_procedure"]' >/dev/null \
  || { echo "FAIL: tools/list names"; echo "$out"; exit 1; }
printf '%s' "$out" | jq -e 'select(.id==2) | (.result.tools[0].annotations.readOnlyHint and .result.tools[1].annotations.readOnlyHint and (.result.tools[2].annotations.readOnlyHint == null))' >/dev/null \
  || { echo "FAIL: decrypt_procedure must stay approval-gated (no readOnlyHint)"; exit 1; }

# 2. Risk Acknowledgment gate: decrypt refused before any connection is attempted.
out=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"decrypt_procedure","arguments":{"procedure":"dbo.X"}}}' \
  | env -u SQL_DECRYPTOR_ALLOW_DBCC_PAGE "$BIN")
printf '%s' "$out" | jq -e 'select(.id==3) | .result.isError and (.result.content[0].text | contains("SQL_DECRYPTOR_ALLOW_DBCC_PAGE"))' >/dev/null \
  || { echo "FAIL: decrypt must be refused without the opt-in"; echo "$out"; exit 1; }

# 3. Opt-in given but credentials missing: the error names the missing variable.
out=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"decrypt_procedure","arguments":{"procedure":"dbo.X"}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_databases","arguments":{}}}' \
  | env -u SQL_DECRYPTOR_SERVER -u SQL_DECRYPTOR_USER -u SQL_DECRYPTOR_PASSWORD -u SQL_DECRYPTOR_DATABASE SQL_DECRYPTOR_ALLOW_DBCC_PAGE=1 "$BIN")
printf '%s' "$out" | jq -e 'select(.id==4) | .result.isError and (.result.content[0].text | contains("SQL_DECRYPTOR_SERVER"))' >/dev/null \
  || { echo "FAIL: missing credentials"; echo "$out"; exit 1; }
printf '%s' "$out" | jq -e 'select(.id==5) | .result.isError and (.result.content[0].text | contains("SQL_DECRYPTOR_SERVER"))' >/dev/null \
  || { echo "FAIL: list_databases without credentials"; echo "$out"; exit 1; }

# 4. Bad procedure names and the page cap are rejected before touching the server.
out=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"decrypt_procedure","arguments":{"procedure":"dbo.Ok;DROP TABLE x"}}}' \
  | env SQL_DECRYPTOR_ALLOW_DBCC_PAGE=1 "$BIN")
printf '%s' "$out" | jq -e 'select(.id==6) | .result.isError' >/dev/null || { echo "FAIL: procedure validation"; echo "$out"; exit 1; }
out=$(printf '%s\n' '{"jsonrpc":"2.0","id":7,"method":"tools/list"}' | env SQL_DECRYPTOR_MAX_PAGES=999 "$BIN")
printf '%s' "$out" | jq -e 'select(.id==7) | .result.tools | length == 3' >/dev/null \
  || { echo "FAIL: tools/list must survive a bad page cap (it is checked when decrypting)"; echo "$out"; exit 1; }
out=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"decrypt_procedure","arguments":{"procedure":"dbo.X"}}}' \
  | env SQL_DECRYPTOR_ALLOW_DBCC_PAGE=1 SQL_DECRYPTOR_MAX_PAGES=999 "$BIN")
printf '%s' "$out" | jq -e 'select(.id==8) | .result.isError and (.result.content[0].text | contains("SQL_DECRYPTOR_MAX_PAGES"))' >/dev/null \
  || { echo "FAIL: page cap above 256 must be refused"; echo "$out"; exit 1; }

# 5. Unknown method is a JSON-RPC error, not a crash.
out=$(printf '%s\n' '{"jsonrpc":"2.0","id":9,"method":"nope"}' | "$BIN")
printf '%s' "$out" | jq -e 'select(.id==9) | .error.code == -32601' >/dev/null || { echo "FAIL: unknown method"; echo "$out"; exit 1; }

echo "OK: MCP protocol, tool wiring, and config gates pass (no database involved)."
