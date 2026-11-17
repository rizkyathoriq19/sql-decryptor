//! Decryptor MCP Server: stdio JSON-RPC, three tools, no desktop app needed.
//!
//! Configuration comes from the environment set by the MCP client:
//!   SQL_DECRYPTOR_SERVER, SQL_DECRYPTOR_USER, SQL_DECRYPTOR_PASSWORD,
//!   SQL_DECRYPTOR_DATABASE  (fill these in ~/.hermes/.env)
//!   SQL_DECRYPTOR_ALLOW_DBCC_PAGE=1  (human opt-in: the Risk Acknowledgment)
//!   SQL_DECRYPTOR_MAX_PAGES  (Page Cap, default 32, max 256, not settable per call)
//!
//! The password is never accepted as a tool argument and never leaves this process
//! except into the sqlcmd child environment.

#[allow(dead_code)]
#[path = "../engine.rs"]
mod engine;

use serde_json::{json, Map, Value};
use std::io::{self, BufRead, Write};

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct Config {
    server: String,
    user: String,
    password: String,
    database: String,
    max_pages: usize,
}

/// The Risk Acknowledgment: a human set this, not the model.
fn dbcc_allowed() -> bool {
    // The flag's presence is the acknowledgment; `hermes config set` may quote it.
    match std::env::var("SQL_DECRYPTOR_ALLOW_DBCC_PAGE") {
        Ok(v) => {
            let v = v.trim().trim_matches('"').to_ascii_lowercase();
            !v.is_empty() && v != "0" && v != "false"
        }
        Err(_) => false,
    }
}

fn env_value(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("{name} is not set in the MCP server environment (put it in ~/.hermes/.env)"))
}

impl Config {
    fn load() -> Result<Self, String> {
        let max_pages = match std::env::var("SQL_DECRYPTOR_MAX_PAGES") {
            Ok(v) if !v.trim().is_empty() => v
                .trim()
                .trim_matches('"')
                .parse::<usize>()
                .map_err(|_| "SQL_DECRYPTOR_MAX_PAGES must be an integer from 1 to 256".to_string())?,
            _ => 32,
        };
        if !(1..=256).contains(&max_pages) {
            return Err("SQL_DECRYPTOR_MAX_PAGES must be from 1 to 256".into());
        }
        Ok(Self {
            server: env_value("SQL_DECRYPTOR_SERVER")?,
            user: env_value("SQL_DECRYPTOR_USER")?,
            password: env_value("SQL_DECRYPTOR_PASSWORD")?,
            database: env_value("SQL_DECRYPTOR_DATABASE")?,
            max_pages,
        })
    }

    fn database(&self, args: &Map<String, Value>) -> Result<String, String> {
        let name = match args.get("database") {
            None | Some(Value::Null) => self.database.clone(),
            Some(Value::String(s)) => s.trim().to_string(),
            Some(_) => return Err("database must be a string".into()),
        };
        engine::check_database_name(&name)?;
        Ok(name)
    }
}

fn tools() -> Value {
    json!([
        {
            "name": "list_databases",
            "description": "List online databases the configured SQL login can access. Read-only.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "list_procedures",
            "description": "List user-defined stored procedures in a database, with object_id and whether each is encrypted. Read-only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "database": {"type": "string", "description": "Database name; defaults to SQL_DECRYPTOR_DATABASE"},
                    "filter": {"type": "string", "description": "Case-insensitive substring match on schema.name"}
                },
                "additionalProperties": false
            },
            "annotations": {"readOnlyHint": true}
        },
        {
            "name": "decrypt_procedure",
            "description": "Decrypt one encrypted stored procedure and return its raw SQL source. Reads pages with DBCC PAGE and needs the operator's opt-in (SQL_DECRYPTOR_ALLOW_DBCC_PAGE=1). Test on a restored database first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "procedure": {"type": "string", "description": "Stored procedure as schema.name, e.g. dbo.MyProcedure"},
                    "database": {"type": "string", "description": "Database name; defaults to SQL_DECRYPTOR_DATABASE"}
                },
                "required": ["procedure"],
                "additionalProperties": false
            }
        }
    ])
}

fn list_databases() -> Result<String, String> {
    let cfg = Config::load()?;
    engine::check_identifier(
        &cfg.server,
        "server",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,:-_\\",
    )?;
    engine::check_identifier(&cfg.user, "user", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")?;
    // Fixed SQL: same query the desktop Connect step runs.
    let query = "SET NOCOUNT ON; SELECT 'DATABASE|\"' + STRING_ESCAPE(name,'json') + '\"' FROM sys.databases WHERE state=0 AND HAS_DBACCESS(name)=1 AND (database_id>4 OR name=DB_NAME()) ORDER BY name;";
    let out = engine::sqlcmd_query(&cfg.server, &cfg.database, &cfg.user, &cfg.password, query)?;
    let mut names: Vec<String> = Vec::new();
    for line in out.lines() {
        let Some(pos) = line.find("DATABASE|") else { continue };
        let raw = line[pos + 9..].trim();
        if let Ok(name) = serde_json::from_str::<String>(raw) {
            names.push(name);
        }
    }
    if names.is_empty() {
        return Err("SQL Server returned no accessible databases".into());
    }
    Ok(names.join("\n"))
}

fn list_procedures(args: &Map<String, Value>) -> Result<String, String> {
    let cfg = Config::load()?;
    let database = cfg.database(args)?;
    let filter = match args.get("filter") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.trim().to_ascii_lowercase(),
        Some(_) => return Err("filter must be a string".into()),
    };
    // Fixed SQL: same query the desktop Browse step runs.
    let query = "SET NOCOUNT ON; SELECT 'PROC|' + SCHEMA_NAME(p.schema_id) + '|' + p.name + '|' + CONVERT(varchar(20),p.object_id) + '|' + CONVERT(varchar(1),ISNULL(OBJECTPROPERTY(p.object_id,'IsEncrypted'),0)) FROM sys.procedures p WHERE p.is_ms_shipped=0 ORDER BY SCHEMA_NAME(p.schema_id),p.name;";
    let out = engine::sqlcmd_query(&cfg.server, &database, &cfg.user, &cfg.password, query)?;
    let mut lines = Vec::new();
    for line in out.lines() {
        let Some(pos) = line.find("PROC|") else { continue };
        let fields: Vec<&str> = line[pos + 5..].trim().split('|').collect();
        if fields.len() != 4 {
            continue;
        }
        let name = format!("{}.{}", fields[0], fields[1]);
        if !filter.is_empty() && !name.to_ascii_lowercase().contains(&filter) {
            continue;
        }
        let state = if fields[3] == "1" { "encrypted" } else { "not encrypted" };
        lines.push(format!("{name} | object_id {} | {state}", fields[2]));
    }
    if lines.is_empty() {
        return Ok(if filter.is_empty() {
            "No user-defined procedures in this database.".to_string()
        } else {
            format!("No procedures match filter '{filter}'.")
        });
    }
    Ok(lines.join("\n"))
}

fn decrypt_procedure(args: &Map<String, Value>) -> Result<String, String> {
    let procedure = match args.get("procedure") {
        Some(Value::String(s)) => s.trim().to_string(),
        _ => return Err("procedure is required (schema.name)".into()),
    };
    let parts: Vec<&str> = procedure.split('.').collect();
    if parts.len() != 2 || parts.iter().any(|p| p.is_empty()) {
        return Err("procedure must be schema.name, e.g. dbo.MyProcedure".into());
    }
    for part in &parts {
        engine::check_identifier(part, "procedure", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")?;
    }
    // Checked before credentials so a missing opt-in is the error the caller sees.
    if !dbcc_allowed() {
        return Err("DBCC PAGE reads are not enabled for this server. A human must set SQL_DECRYPTOR_ALLOW_DBCC_PAGE=1 in the MCP server configuration after testing on a restored database.".into());
    }
    let cfg = Config::load()?;
    let database = cfg.database(args)?;
    let tmp = tempfile::tempdir().map_err(|e| format!("could not create a temporary directory: {e}"))?;
    let output = tmp.path().join("decrypted.sql").to_string_lossy().to_string();
    engine::decrypt_to_file(&cfg.server, &database, &cfg.user, &cfg.password, &procedure, &output, cfg.max_pages)?;
    let source = std::fs::read_to_string(&output).map_err(|e| format!("cannot read decrypted output: {e}"))?;
    // Same output validation as the desktop backend.
    if source.trim().len() < 30 || source.len() > 8 * 1024 * 1024 {
        return Err("decrypted SQL output failed size validation".into());
    }
    // tempfile::TempDir drops here and removes the intermediate file.
    Ok(source)
}

fn text_result(text: String) -> Value {
    json!({"content": [{"type": "text", "text": text}]})
}

fn error_result(message: String) -> Value {
    json!({"content": [{"type": "text", "text": message}], "isError": true})
}

fn call_tool(params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let empty = Map::new();
    let args = params.get("arguments").and_then(Value::as_object).unwrap_or(&empty);
    let outcome = match name {
        "list_databases" => list_databases(),
        "list_procedures" => list_procedures(args),
        "decrypt_procedure" => decrypt_procedure(args),
        other => return error_result(format!("unknown tool {other}")),
    };
    match outcome {
        Ok(text) => text_result(text),
        Err(message) => error_result(message),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ignoring unparseable request: {e}");
                continue;
            }
        };
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("").to_string();
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        let result = match method.as_str() {
            "initialize" => {
                let asked = params.get("protocolVersion").and_then(Value::as_str);
                json!({
                    "protocolVersion": asked.unwrap_or("2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "sql-decryptor", "version": VERSION}
                })
            }
            "ping" => json!({}),
            "tools/list" => json!({"tools": tools()}),
            "tools/call" => call_tool(&params),
            m if m.starts_with("notifications/") => continue,
            other => {
                if let Some(id) = id {
                    let reply = json!({"jsonrpc": "2.0", "id": id,
                        "error": {"code": -32601, "message": format!("unknown method {other}")}});
                    let _ = writeln!(stdout, "{reply}");
                    let _ = stdout.flush();
                }
                continue;
            }
        };
        // Requests without an id are notifications: never answered.
        let Some(id) = id else { continue };
        let reply = json!({"jsonrpc": "2.0", "id": id, "result": result});
        if writeln!(stdout, "{reply}").is_err() || stdout.flush().is_err() {
            break;
        }
    }
}
