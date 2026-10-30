// SQL Decryptor MVP - Tauri 2 commands. No SQL is executed from the frontend.
// All SQL commands below are fixed read-only metadata queries, except the
// experimental internal DBCC PAGE read delegated to the user's Rust engine.
mod engine;

use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
};

static DECRYPT_BUSY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Connection {
    server: String,
    database: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerInfo {
    database: String,
    product_version: String,
    is_sysadmin: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Procedure {
    schema: String,
    name: String,
    object_id: i32,
    encrypted: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Decryption {
    procedure: String,
    source: String,
    bytes: usize,
    note: String,
}

fn check_identifier(value: &str, label: &str, permitted: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 128 ||
        !value.bytes().all(|b| permitted.as_bytes().contains(&b)) ||
        !value.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err(format!("Invalid {label}: use ASCII letters/numbers and permitted punctuation"));
    }
    Ok(())
}

fn validate(conn: &Connection) -> Result<(), String> {
    check_identifier(&conn.server, "server", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,:-_\\")?;
    check_identifier(&conn.database, "database", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")?;
    check_identifier(&conn.username, "username", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")?;
    if conn.password.is_empty() || conn.password.len() > 4096 {
        return Err("A password is required (maximum 4096 characters)".into());
    }
    Ok(())
}

fn sqlcmd(conn: &Connection, query: &str) -> Result<String, String> {
    validate(conn)?;
    // Environment is applied to the child process only, never to the global app.
    // Do not pass a password to the command-line arguments or a shell.
    let output = Command::new("sqlcmd")
        .env("SQLCMDPASSWORD", &conn.password)
        .args([
            "-S", &conn.server, "-U", &conn.username, "-d", &conn.database,
            "-h", "-1", "-W", "-s", "|", "-w", "65535",
            "-l", "8", "-t", "15", "-b", "-Q", query,
        ])
        .output()
        .map_err(|e| format!("Could not run sqlcmd ({e}). Install sqlcmd and add it to PATH before launching the app."))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() || stdout.contains("Sqlcmd: Error:") || stderr.contains("Sqlcmd: Error:") {
        return Err(format!("SQL Server request failed: {}", format!("{stdout} {stderr}").chars().take(900).collect::<String>()));
    }
    Ok(stdout)
}

fn records<'a>(s: &'a str, prefix: &str) -> Vec<Vec<&'a str>> {
    s.lines().filter_map(|line| line.find(prefix).map(|pos| {
        line[pos + prefix.len()..].trim().split('|').collect::<Vec<_>>()
    })).collect()
}

#[tauri::command]
async fn connect_database(config: Connection) -> Result<ServerInfo, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let query = "SET NOCOUNT ON; SELECT 'CONNECTED|' + DB_NAME() + '|' + CONVERT(varchar(128),SERVERPROPERTY('ProductVersion')) + '|' + CONVERT(varchar(1),IS_SRVROLEMEMBER('sysadmin'));";
        let result = sqlcmd(&config, query)?;
        let rows = records(&result, "CONNECTED|");
        let row = rows.first().ok_or("SQL Server returned no connection metadata")?;
        if rows.len() != 1 || row.len() != 3 { return Err("Unexpected connection metadata format".into()); }
        Ok(ServerInfo {
            database: row[0].to_string(), product_version: row[1].to_string(),
            is_sysadmin: row[2] == "1",
        })
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn browse_procedures(config: Connection) -> Result<Vec<Procedure>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        // Fixed SQL, no user-provided identifier interpolation. Top 1000 bounded browse.
        let query = "SET NOCOUNT ON; SELECT TOP (1000) 'PROC|' + SCHEMA_NAME(p.schema_id) + '|' + p.name + '|' + CONVERT(varchar(20),p.object_id) + '|' + CONVERT(varchar(1),ISNULL(OBJECTPROPERTY(p.object_id,'IsEncrypted'),0)) FROM sys.procedures p WHERE p.is_ms_shipped=0 ORDER BY SCHEMA_NAME(p.schema_id),p.name;";
        let output = sqlcmd(&config, query)?;
        let mut procedures = Vec::new();
        for row in records(&output, "PROC|") {
            if row.len() != 4 { continue; }
            if let Ok(object_id) = row[2].parse::<i32>() {
                procedures.push(Procedure { schema: row[0].into(), name: row[1].into(), object_id, encrypted: row[3] == "1" });
            }
        }
        Ok(procedures)
    }).await.map_err(|e| e.to_string())?
}

struct BusyGuard;
impl BusyGuard {
    fn acquire() -> Result<Self, String> {
        DECRYPT_BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| "Another decryption is already running".into())
    }
}
impl Drop for BusyGuard {
    fn drop(&mut self) { DECRYPT_BUSY.store(false, Ordering::Release); }
}

#[tauri::command]
async fn decrypt_procedure(config: Connection, procedure: String, acknowledge_risk: bool) -> Result<Decryption, String> {
    if !acknowledge_risk { return Err("You must acknowledge the experimental DBCC PAGE read before decrypting".into()); }
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = BusyGuard::acquire()?;
        validate(&config)?;
        let pieces: Vec<&str> = procedure.split('.').collect();
        if pieces.len() != 2 { return Err("Procedure must be schema.name".into()); }
        for part in pieces { check_identifier(part, "procedure", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")?; }
        let tmp = tempfile::tempdir().map_err(|e| format!("Could not create temporary directory: {e}"))?;
        let output = tmp.path().join("decrypted.sql");
        let output_string = output.to_string_lossy().to_string();
        // Reuse the submitted Rust decryptor's SHA1/RC4, DBCC parser, bounds, and checks.
        engine::decrypt_to_file(&config.server, &config.database, &config.username,
            &config.password, &procedure, &output_string, 32)?;
        let source = std::fs::read_to_string(&output).map_err(|e| format!("Cannot read decrypted output: {e}"))?;
        if source.trim().len() < 30 || source.len() > 8 * 1024 * 1024 {
            return Err("Decrypted SQL output failed size validation".into());
        }
        let bytes = source.len();
        // tempfile::TempDir drops here and removes the decrypted intermediate file.
        Ok(Decryption {
            procedure, source, bytes,
            note: "Decrypted by the existing Rust engine. Read for analysis only; do not execute on production.".into(),
        })
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
async fn export_sql(path: String, content: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if content.is_empty() || content.len() > 8 * 1024 * 1024 { return Err("Invalid SQL export size".into()); }
        let dest = Path::new(&path);
        if !dest.is_absolute() || dest.extension().and_then(|x| x.to_str()).map(|e| e.eq_ignore_ascii_case("sql")) != Some(true) {
            return Err("Choose an absolute path ending in .sql".into());
        }
        // Never overwrite an existing source file; users must pick a new file name.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(dest).map_err(|e| format!("Could not create file (existing files cannot be overwritten): {e}"))?;
        file.write_all(content.as_bytes()).map_err(|e| format!("Could not write SQL file: {e}"))?;
        Ok(dest.display().to_string())
    }).await.map_err(|e| e.to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![connect_database, browse_procedures, decrypt_procedure, export_sql])
        .run(tauri::generate_context!())
        .expect("failed to run SQL Decryptor desktop");
}
