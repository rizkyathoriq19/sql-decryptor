# MCP server as a Rust binary in the Tauri crate, with config-level Risk Acknowledgment

Status: accepted (2026-11-17)

AI agents need to decrypt procedures without the desktop app. We build a stdio MCP server as a second Rust binary in `src-tauri`, calling the existing `engine` module directly, rather than a Node/TS server using the MCP SDK (which would have to shell out to a Rust CLI) or the `rmcp` crate (a new dependency for three tools). The Connection, including the password, comes from the MCP server's environment and is never accepted as a tool argument, so the password never reaches the model.

The desktop app's per-Decryption Risk Acknowledgment does not carry over. A tool argument such as `acknowledge_risk: true` would be filled in by the model and therefore mean nothing. Instead, a human opts in once by setting an allow flag and the Page Cap in the server's configuration. The model cannot raise the Page Cap. Each call is then confirmed through the MCP client's own tool-approval prompt. In Hermes this means the server is registered `trust: untrusted` and `decrypt_procedure` carries no `readOnlyHint`; the listing tools are marked read-only.

## Considered options

- Node/TS + `@modelcontextprotocol/sdk`: rejected because it duplicates the runtime and leaves the algorithm reachable only through a subprocess.
- Rust + `rmcp`: rejected for now because it adds a dependency. Revisit if the server needs resources, prompts, or streaming.
- The existing `engine.rs` CLI only: rejected because it cannot list databases or procedures for an agent.

## Consequences

- The process-local "one Decryption at a time" guard does not span the desktop app and the MCP server; each enforces its own.
- Changing the Connection or the Page Cap means editing the MCP config and restarting the server.
