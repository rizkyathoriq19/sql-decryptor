# SQL Decryptor — Tauri 2 + React + IBM Carbon MVP

Desktop MVP for **connect → browse procedures → decrypt → export**. The UI is built with React/TypeScript, IBM Carbon, and Tauri 2; the backend uses the **user's `sqltextdecrypt_remote.rs` engine**, copied to `src-tauri/src/engine.rs` and adapted so it can be called directly as a Rust module.

> **Status:** source project complete. Source-level verification on Linux/Omarchy: `npm run build` (tsc + Vite) passes, `cargo check` reports 0 errors, and 8 engine unit tests pass. **A full Tauri bundle build, real GUI integration, and live SQL Server remain unverified**; test against a restored database with DBA authorization first.

## Features

1. **Connect**: opens a real SQL Server connection through the installed `sqlcmd`. Reads `DB_NAME()`, `ProductVersion`, and the sysadmin role.
2. **Browse**: reads all user-defined procedures in the selected database, filters by name, and detects `IsEncrypted`. After connecting, the database field becomes a dropdown of accessible online databases.
3. **Decrypt**: uses SHA-1/RC4/UTF-16LE and ciphertext extraction through bounded `DBCC PAGE` calls from the existing engine. Limited to **32 unique pages**, one decryption at a time, and an acknowledgment checkbox is required for every operation. Output is strictly validated before display.
4. **Export**: uses the native save dialog for `.sql` files and **never overwrites an existing file**.

All SQL source shown in the preview is rendered as plain text only. **There is no feature to execute SQL source or modify stored procedures.**

## Key structure

```
src/App.tsx                 Carbon interface and user flow
src/styles.scss             Enterprise desktop styling
src-tauri/src/lib.rs        Tauri commands, sqlcmd connection, listing, export
src-tauri/src/engine.rs     Reused Rust decryptor (original algorithm + modified integration)
src-tauri/tauri.conf.json   Desktop configuration
src-tauri/capabilities/     Native dialog permission
```

## Setup on Omarchy (Arch Linux)

Tauri v2 requires a recent Rust toolchain and WebKitGTK 4.1. Install the dependencies if they are missing:

```bash
sudo pacman -S --needed \
  webkit2gtk-4.1 base-devel curl wget file openssl \
  appmenu-gtk-module libappindicator-gtk3 librsvg xdotool
```

The latest Tauri dialog plugin requires Rust >= 1.90. Run `rustup update stable` if needed.

```bash
rustc --version
cargo --version
node --version
sqlcmd --help
```

**Make sure `sqlcmd` is available on the `PATH` of the terminal that launches the app.** If the `sqlcmd` binary lives in `~/.local/bin`:

```bash
export PATH="$HOME/.local/bin:$PATH"
command -v sqlcmd
```

When the app is opened from a desktop launcher, `PATH` may differ from the terminal; for now, launch it from a terminal.

## Running the app

Extract the ZIP, enter the project directory, then:

```bash
npm install
npm run desktop
```

This runs Vite and Tauri in development mode. The Tauri CLI downloads and compiles the Rust dependencies on first run. To build a distribution:

```bash
npm run desktop:build
```

If you only need to debug the frontend, `npm run dev` opens the HTML page, but **connect/decrypt/export are unavailable** in a regular browser because they require the Tauri runtime.

### Testing the Rust engine separately

```bash
rustc --edition=2021 --test src-tauri/src/engine.rs -o /tmp/sql_decryptor_tests
/tmp/sql_decryptor_tests
```

Eight engine unit tests pass (SHA-1, RC4, .NET GUID, hex, round-trip, index pointer, strict UTF-16, and the DBCC parser). These tests are **not** proof that extraction will work on every SQL Server version.

## Usage

Open the app and fill in Server (e.g. `localhost` or `host\instance`), Database (database name), Username (SQL Server login), and password (not stored). Press **Connect**; choose a different database from the dropdown to load its procedures immediately. Select an encrypted procedure, then **Decrypt**. The dialog asks for acknowledgment before the `DBCC PAGE` operation. Once the source appears, press **Export .sql** to choose a save location. The SQL file is for analysis only; **do not execute it in production**.

## Limits and security

- The SQL Server connection uses `sqlcmd` as a child process, not PowerShell. Server/database/user input is restricted; the metadata queries built by the app are fixed.
- At startup the app checks for `sqlcmd` and shows a persistent warning with a **Check again** action if it is missing. The AppImage/installer does not bundle `sqlcmd`; restart the app after changing `PATH`.
- The password exists only in frontend memory for the session, is passed over Tauri IPC, and is forwarded to the **sqlcmd child process environment**. It is not sent via the `-P` argument, stored in a configuration file, or recorded in logs. Clearing the field or closing the app removes the value from that process.
- The engine **does not intentionally write to the database** (no DDL/DML). However, `DBCC PAGE` is an undocumented internal operation and can consume server resources. **There is no guarantee of zero downtime.** Test on a restored database and obtain DBA permission before using it in production.
- `max_pages` for the GUI is pinned to 32. If it is too small for a large procedure, the process refuses instead of raising it automatically. The page and internal LOB parsers need cross-version validation.
- The GUI does not open a connection automatically at app startup. Only selecting an encrypted procedure can request decryption.
- `src-tauri/src/engine.rs` still uses the internal `sysobjvalues` index mapping (`object_id=60`, `index_id=1`) based on inspected SQL Server 2019 metadata; it is not guaranteed to work on other SQL Server versions.
- The procedure list loads all user-defined procedures in the selected database; the MVP has no pagination or data table editor.
- Export uses exclusive `create_new`; if the file already exists, choose a different name.
- This project includes no credentials, ciphertext, decrypted eConnect source, or server access.

## Original engine implementation

The source in `src-tauri/src/engine.rs` comes from the previously provided `sqltextdecrypt_remote.rs` file. The SHA-1, RC4, little-endian .NET GUID, decoder, and `DBCC PAGE` parser are preserved. Minimal adaptations for the GUI:

- accepts the password as an internal function argument (not a global environment variable);
- passes the password only to the `sqlcmd` process invoked by Rust;
- adds the `decrypt_to_file` function called by Tauri;
- does not use a literal allocation ID: the IN_ROW `sysobjvalues` allocation lookup is performed per database;
- the temporary source is written to the OS temporary directory, read, and the directory is deleted automatically.

## Reference documentation

- Tauri 2: https://v2.tauri.app/start/prerequisites/
- Tauri 2 commands: https://v2.tauri.app/develop/calling-rust/
- Tauri native save dialog: https://v2.tauri.app/plugin/dialog/
- IBM Carbon React: https://github.com/carbon-design-system/carbon/tree/main/packages/react

**Source-level MVP, not yet verified end-to-end against SQL Server.**
