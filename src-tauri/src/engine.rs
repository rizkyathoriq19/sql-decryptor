//! Decrypt the text of SQL Server modules created WITH ENCRYPTION.
//!
//! Mirrors the logic read from SqlTextDecryptor.Decrypt in the decompiled
//! dbForge SQL Decryptor:
//!
//!   key  = SHA1( family_guid (16 bytes, .NET Guid.ToByteArray order)
//!                || object_id (4 bytes, little-endian)
//!                || subobjid  (2 bytes, little-endian) )
//!   text = UTF-16LE( RC4(key, imageval) )
//!
//! No external crates. Build:  rustc -O sqltextdecrypt.rs
//! Test:                       rustc --test sqltextdecrypt.rs && ./sqltextdecrypt
//!
//! Only use this on objects in databases you own or are authorized to manage.

use std::io::Read;
use std::process::exit;

const USAGE: &str = "\
Usage: sqltextdecrypt --family-guid <GUID> --object-id <ID> [--number <N>] --hex <HEX|->

  --family-guid  database family GUID (e.g. 00112233-4455-6677-8899-aabbccddeeff)
  --object-id    object_id of the encrypted module
  --number       subobjid / procedure number (default 1)
  --hex          imageval as hex (0x prefix ok), or '-' to read stdin

Remote mode (experimental, use on RESTORED database first):
  sqltextdecrypt --server HOST --database DB --user sa --procedure dbo.NAME --inspect
  sqltextdecrypt --server HOST --database DB --user sa --procedure dbo.NAME \
    --allow-dbcc-page --max-pages 128 --output FILE.sql
  Requires sqlcmd in PATH and SQLCMDPASSWORD environment variable.
  Uses bounded, undocumented DBCC PAGE reads. No DAC or database writes.
";

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn rc4(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
            b ^ k
        })
        .collect()
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let digits = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if digits.len() % 2 != 0 {
        return Err("hex string has an odd number of digits".into());
    }
    digits
        .as_bytes()
        .chunks(2)
        .map(|p| {
            let s = std::str::from_utf8(p).map_err(|e| e.to_string())?;
            u8::from_str_radix(s, 16).map_err(|_| format!("invalid hex digits: {s:?}"))
        })
        .collect()
}

/// Parse a textual GUID into .NET `Guid.ToByteArray()` order
/// (first three groups little-endian, remaining bytes as written).
fn guid_to_dotnet_bytes(text: &str) -> Result<[u8; 16], String> {
    let compact: String = text
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .chars()
        .filter(|c| *c != '-')
        .collect();
    if compact.len() != 32 {
        return Err(format!("GUID must have 32 hex digits, got {}", compact.len()));
    }
    let be = decode_hex(&compact)?;
    let mut le = [0u8; 16];
    for i in 0..4 {
        le[i] = be[3 - i];
    }
    le[4] = be[5];
    le[5] = be[4];
    le[6] = be[7];
    le[7] = be[6];
    le[8..].copy_from_slice(&be[8..]);
    Ok(le)
}

fn derive_key(guid_dotnet: &[u8; 16], object_id: u32, number: u16) -> [u8; 20] {
    let mut buf = [0u8; 22];
    buf[..16].copy_from_slice(guid_dotnet);
    buf[16..20].copy_from_slice(&object_id.to_le_bytes());
    buf[20..22].copy_from_slice(&number.to_le_bytes());
    sha1(&buf)
}

fn decrypt(ctext: &[u8], guid_dotnet: &[u8; 16], object_id: u32, number: u16) -> String {
    let plain = rc4(ctext, &derive_key(guid_dotnet, object_id, number));
    let units: Vec<u16> = plain
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}\n\n{USAGE}");
    exit(2);
}

// Experimental, bounded, read-only-page extractor. Requires existing sqlcmd executable.
// No DAC, DDL, DML, TRACEON or server config changes.
use std::collections::{HashSet, HashMap};
use std::io::Write;
use std::process::Command;
use std::path::Path;

const PAGE_SIZE: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PageRef { file: u16, page: u32 }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct LobRef { file: u16, page: u32, slot: u16 }

fn get_u16(b: &[u8], pos: usize) -> Result<u16, String> {
    let x = b.get(pos..pos + 2).ok_or_else(|| "truncated u16".to_string())?;
    Ok(u16::from_le_bytes([x[0], x[1]]))
}
fn get_i32(b: &[u8], pos: usize) -> Result<i32, String> {
    let x = b.get(pos..pos + 4).ok_or_else(|| "truncated i32".to_string())?;
    Ok(i32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}
fn parse_ptr(b: &[u8]) -> Result<PageRef, String> {
    if b.len() < 6 { return Err("page pointer too short".into()); }
    let page = get_i32(b, 0)?;
    if page <= 0 { return Err("invalid page pointer".into()); }
    let file = get_u16(b, 4)?;
    if file == 0 { return Err("invalid file id".into()); }
    Ok(PageRef { file, page: page as u32 })
}
fn parse_sqlcmd_marker(output: &str) -> Result<Vec<String>, String> {
    let mut matches = output.lines().filter_map(|line| {
        line.find("RESULT|").map(|idx| line[idx + 7..].trim())
    });
    let first = matches.next().ok_or_else(|| format!("sqlcmd did not return RESULT marker. Output: {}", output.chars().take(350).collect::<String>()))?;
    if matches.next().is_some() { return Err("multiple RESULT markers".into()); }
    Ok(first.split('|').map(|s| s.trim().to_string()).collect())
}
fn hex_from_sql(s: &str) -> Result<Vec<u8>, String> {
    decode_hex(s)
}
fn slot_offset(page: &[u8], slot: usize) -> Result<usize, String> {
    if page.len() != PAGE_SIZE { return Err("page is not 8192 bytes".into()); }
    let count = get_u16(page, 22)? as usize;
    if slot >= count || count > 4000 { return Err(format!("invalid slot {slot}/{count}")); }
    let offset = get_u16(page, PAGE_SIZE - 2 - slot * 2)? as usize;
    if !(96..PAGE_SIZE - 32).contains(&offset) { return Err(format!("invalid record offset {offset}")); }
    Ok(offset)
}
fn dump_from_dbcc(out: &str, expected: PageRef) -> Result<Vec<u8>, String> {
    let mut dump = Vec::new();
    let mut has_identity = false;
    for line in out.lines() {
        let fields: Vec<&str> = line.splitn(4, '|').collect();
        if fields.len() != 4 { continue; }
        let object = fields[1].trim();
        let field = fields[2].trim();
        let value = fields[3].trim();
        if field == "m_pageId" && value.contains(&format!("({}:{})", expected.file, expected.page)) {
            has_identity = true;
        }
        if object.starts_with("Memory Dump") { dump.push(value); }
    }
    if !has_identity { return Err("DBCC PAGE identity missing or does not match requested page".into()); }
    let mut raw = vec![0u8; PAGE_SIZE];
    let mut seen = vec![false; PAGE_SIZE];
    let mut covered = 0usize;
    let mut base = None;
    for line in dump {
        let Some((addr, bytes)) = line.split_once(':') else { continue };
        let a = addr.trim();
        if a.len() < 8 || a.len() > 16 || !a.as_bytes().iter().all(|x| x.is_ascii_hexdigit()) { continue; }
        let address = u64::from_str_radix(a, 16).map_err(|e| e.to_string())?;
        let base_addr = *base.get_or_insert(address);
        let Some(mut offset) = address.checked_sub(base_addr).map(|v| v as usize) else { continue; };
        if offset >= PAGE_SIZE { continue; }
        for token in bytes.split_whitespace() {
            if token.len() != 8 || !token.as_bytes().iter().all(|x| x.is_ascii_hexdigit()) { break; }
            if offset + 4 > PAGE_SIZE { break; }
            let group = decode_hex(token)?;
            for b in group {
                raw[offset] = b;
                if !seen[offset] { seen[offset] = true; covered += 1; }
                offset += 1;
            }
        }
    }
    if covered != PAGE_SIZE { return Err(format!("incomplete DBCC memory dump: {covered}/8192 bytes")); }
    Ok(raw)
}

struct Client {
    server: String,
    database: String,
    user: String,
    password: String,
    max_pages: usize,
    page_count: usize,
    page_cache: HashMap<PageRef, Vec<u8>>,
}
impl Client {
    fn query(&self, sql: &str) -> Result<String, String> {
        // SQLCMDPASSWORD is inherited; credentials never appear in arguments/logs.
        let output = Command::new("sqlcmd")
            .env("SQLCMDPASSWORD", &self.password)
            .args(["-S", &self.server, "-U", &self.user, "-d", &self.database,
                   "-h", "-1", "-W", "-s", "|", "-w", "65535", "-l", "8", "-t", "15", "-b", "-Q", sql])
            .output().map_err(|e| format!("unable to launch sqlcmd: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if !output.status.success() || stdout.contains("Sqlcmd: Error:") || stderr.contains("Sqlcmd: Error:") {
            return Err(format!("sqlcmd failed: {} {}", stdout.chars().take(400).collect::<String>(), stderr.chars().take(400).collect::<String>()));
        }
        Ok(stdout)
    }
    fn read_page(&mut self, r: PageRef) -> Result<Vec<u8>, String> {
        if let Some(p) = self.page_cache.get(&r) { return Ok(p.clone()); }
        if self.page_count >= self.max_pages {
            return Err(format!("page read cap {} reached; refusing to scan more pages", self.max_pages));
        }
        let db = self.database.replace(']', "]]");
        let sql = format!("SET NOCOUNT ON; DBCC PAGE ([{db}], {}, {}, 2) WITH TABLERESULTS, NO_INFOMSGS;", r.file, r.page);
        let raw = self.query(&sql)?;
        let page = dump_from_dbcc(&raw, r).map_err(|e| format!("DBCC PAGE {}:{}: {e}", r.file, r.page))?;
        self.page_count += 1;
        self.page_cache.insert(r, page.clone());
        Ok(page)
    }
}

fn leaf_for_object(client: &mut Client, root: PageRef, object_id: i32) -> Result<PageRef, String> {
    let mut here = root;
    let mut visited = HashSet::new();
    for _ in 0..16 {
        if !visited.insert(here) { return Err("index page loop".into()); }
        let page = client.read_page(here)?;
        match page[1] {
            1 => return Ok(here),
            2 => {
                let count = get_u16(&page, 22)? as usize;
                if count == 0 { return Err("empty index page".into()); }
                let mut chosen = None;
                for slot in 0..count {
                    let p = slot_offset(&page, slot)?;
                    if p + 20 > PAGE_SIZE { return Err("truncated index entry".into()); }
                    let child = parse_ptr(&page[p + 14..p + 20])?;
                    if slot == 0 { chosen = Some(child); continue; }
                    let valclass = page[p + 1];
                    let key_id = get_i32(&page, p + 2)?;
                    if valclass < 1 || (valclass == 1 && key_id < object_id) { chosen = Some(child); }
                    else { break; }
                }
                here = chosen.ok_or("no index child selected")?;
            }
            typ => return Err(format!("unexpected index page type {typ}")),
        }
    }
    Err("index depth > 16".into())
}

struct ValueRow { colid: i32, is_lob: bool, value: Vec<u8> }
fn rows_for_object(page: &[u8], object_id: i32) -> Result<(Vec<ValueRow>, bool), String> {
    if page[1] != 1 { return Err("expected data page".into()); }
    let count = get_u16(page, 22)? as usize;
    let mut rows = Vec::new();
    let mut past = false;
    for slot in 0..count {
        let p = slot_offset(page, slot)?;
        if p + 17 >= PAGE_SIZE { continue; }
        let valclass = page[p + 4];
        let id = get_i32(page, p + 5)?;
        if valclass > 1 || (valclass == 1 && id > object_id) { past = true; }
        if valclass != 1 || id != object_id { continue; }
        let fixed = get_u16(page, p + 2)? as usize;
        if fixed < 4 || p + fixed + 2 >= PAGE_SIZE { return Err("invalid record fixed length".into()); }
        let col_count = get_u16(page, p + fixed)? as usize;
        let var_count_pos = p + fixed + 2 + (col_count + 7) / 8;
        let var_count = get_u16(page, var_count_pos)? as usize;
        if var_count < 1 || var_count > 128 { return Err("invalid record variable column count".into()); }
        let offsets = var_count_pos + 2;
        if offsets + var_count * 2 > PAGE_SIZE { return Err("truncated offsets".into()); }
        let end_raw = get_u16(page, offsets + (var_count - 1) * 2)?;
        let previous = if var_count >= 2 { get_u16(page, offsets + (var_count - 2) * 2)? as usize }
            else { offsets + var_count * 2 - p };
        let start = previous & 0x7fff;
        let end = (end_raw & 0x7fff) as usize;
        if start > end || p + end > PAGE_SIZE { return Err("invalid imageval extent".into()); }
        rows.push(ValueRow { colid: get_i32(page, p + 9)?, is_lob: (end_raw & 0x8000) != 0, value: page[p + start..p + end].to_vec() });
    }
    Ok((rows, past))
}
fn image_rows(client: &mut Client, root: PageRef, object_id: i32) -> Result<Vec<ValueRow>, String> {
    let mut here = leaf_for_object(client, root, object_id)?;
    let mut visited = HashSet::new();
    let mut row_ids = HashSet::new();
    let mut all = Vec::new();
    for _ in 0..64 {
        if !visited.insert(here) { return Err("leaf chain loop".into()); }
        let page = client.read_page(here)?;
        let (rows, past) = rows_for_object(&page, object_id)?;
        for row in rows {
            if !row_ids.insert(row.colid) { return Err("duplicate subobjid".into()); }
            all.push(row);
        }
        if past { break; }
        let next_raw = &page[16..22];
        let next = match parse_ptr(next_raw) { Ok(x) => x, Err(_) => break };
        here = next;
    }
    if all.is_empty() { return Err("index seek did not find any encrypted definition rows; no full table scan performed".into()); }
    Ok(all)
}
fn child_from(b: &[u8], off: usize) -> Result<LobRef, String> {
    let p = get_i32(b, off)?;
    let f = get_u16(b, off + 4)?;
    let slot = get_u16(b, off + 6)?;
    if p <= 0 || f == 0 { return Err("invalid LOB child pointer".into()); }
    Ok(LobRef { file: f, page: p as u32, slot })
}
fn read_lob_node(client: &mut Client, node: LobRef, depth: usize, seen: &mut HashSet<LobRef>, out: &mut Vec<u8>) -> Result<(), String> {
    if depth > 32 { return Err("LOB tree depth > 32".into()); }
    if !seen.insert(node) { return Err("LOB pointer loop or duplicate".into()); }
    let page = client.read_page(PageRef { file: node.file, page: node.page })?;
    let p = slot_offset(&page, node.slot as usize)?;
    if p + 20 > PAGE_SIZE { return Err("truncated LOB record".into()); }
    let typ = get_u16(&page, p + 12)?;
    match typ {
        3 => {
            let rec_len = get_i32(&page, p + 2)?;
            if rec_len < 14 || p.checked_add(rec_len as usize).map_or(true, |end| end > PAGE_SIZE) { return Err("invalid LOB data length".into()); }
            if out.len() + rec_len as usize > 8 * 1024 * 1024 { return Err("LOB output too large".into()); }
            out.extend_from_slice(&page[p + 14..p + rec_len as usize]);
        }
        2 => {
            let count = get_i32(&page, p + 16)?;
            if count < 1 || count > 512 || p + 20 + count as usize * 16 > PAGE_SIZE { return Err("invalid LOB internal entry count".into()); }
            let mut children = Vec::new();
            for i in 0..count as usize { children.push(child_from(&page, p + 20 + i * 16 + 8)?); }
            // Preserve in-order traversal; do not concatenate breadth-first.
            for child in children { read_lob_node(client, child, depth + 1, seen, out)?; }
        }
        _ => return Err(format!("unexpected LOB record type {typ}")),
    }
    Ok(())
}
fn assemble_cipher(client: &mut Client, row: &ValueRow) -> Result<Vec<u8>, String> {
    if !row.is_lob { return Ok(row.value.clone()); }
    let root = &row.value;
    if root.len() < 24 || (root.len() - 12) % 12 != 0 { return Err("invalid LOB root".into()); }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for off in (12..root.len()).step_by(12) {
        // Root link is cumulative_len:u32, page_id:i32, file_id:u16, slot_id:u16.
        let child = child_from(root, off + 4)?;
        read_lob_node(client, child, 0, &mut seen, &mut out)?;
    }
    if out.is_empty() || out.len() % 2 != 0 { return Err("empty/odd-length ciphertext from LOB".into()); }
    Ok(out)
}
fn decrypt_strict(blob: &[u8], guid: &[u8; 16], objid: u32, number: u16, name: Option<&str>) -> Result<String, String> {
    if blob.is_empty() || blob.len() % 2 != 0 { return Err("ciphertext must contain an even, nonzero number of bytes".into()); }
    let data = rc4(blob, &derive_key(guid, objid, number));
    let utf16: Vec<u16> = data.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    let src = String::from_utf16(&utf16).map_err(|_| "invalid UTF-16 result: wrong key or corrupt ciphertext".to_string())?;
    if let Some(procedure) = name {
        let prefix: String = src.chars().take(2500).collect::<String>().to_ascii_lowercase();
        let procedure = procedure.to_ascii_lowercase();
        if !prefix.contains(&procedure) || !["create", "alter", "procedure", "proc"].iter().any(|x| prefix.contains(x)) {
            return Err("decrypted text does not resemble the expected procedure; nothing saved".into());
        }
    }
    Ok(src)
}
fn secure_write(path: &str, data: &[u8]) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; opts.mode(0o600); }
    let mut file = opts.open(Path::new(path)).map_err(|e| format!("cannot create {path} (won't overwrite): {e}"))?;
    file.write_all(data).map_err(|e| format!("cannot write {path}: {e}"))
}
fn checked_token(s: &str, allowed: &str, label: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 128 || !s.as_bytes().iter().all(|b| allowed.as_bytes().contains(b)) {
        return Err(format!("invalid {label}: use ASCII letters/numbers and allowed punctuation only"));
    }
    Ok(())
}
fn remote_run(server: String, database: String, user: String, procedure: String, output: Option<String>, inspect: bool, allow_pages: bool, max_pages: usize, password: String) -> Result<(), String> {
    checked_token(&server, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,:-_\\", "server")?;
    checked_token(&database, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-", "database")?;
    checked_token(&user, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-", "user")?;
    checked_token(&procedure, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.", "procedure")?;
    let parts: Vec<&str> = procedure.split('.').collect();
    if parts.len() != 2 || parts.iter().any(|s| s.is_empty()) { return Err("procedure must be schema.name, e.g. dbo.MyProcedure".into()); }
    if !inspect && (!allow_pages || output.is_none()) {
        return Err("extraction requires --allow-dbcc-page and --output; test on a RESTORED database first".into());
    }
    if !(1..=256).contains(&max_pages) { return Err("max-pages must be 1..=256".into()); }
    if password.is_empty() { return Err("password must not be empty".into()); }
    let mut db = Client { server, database, user, password, max_pages, page_count: 0, page_cache: HashMap::new() };
    let name = parts[1];
    let sql = format!("SET NOCOUNT ON; SELECT 'RESULT|' + CONVERT(varchar(20),o.object_id) + '|' + CONVERT(varchar(36),drs.family_guid) + '|' + CONVERT(varchar(1),OBJECTPROPERTY(o.object_id,'IsEncrypted')) FROM sys.objects AS o JOIN sys.database_recovery_status AS drs ON drs.database_id=DB_ID() WHERE o.object_id=OBJECT_ID(N'{}') AND EXISTS(SELECT 1 FROM sys.sql_modules AS m WHERE m.object_id=o.object_id);", procedure);
    let meta = parse_sqlcmd_marker(&db.query(&sql)?)?;
    if meta.len() != 3 { return Err(format!("unexpected metadata columns: {meta:?}")); }
    if meta[2] != "1" { return Err("target module is not marked encrypted".into()); }
    let objid: i32 = meta[0].parse().map_err(|_| "invalid object id".to_string())?;
    let guid = guid_to_dotnet_bytes(&meta[1])?;
    eprintln!("Target {procedure}, object_id={}, encrypted=1, database={}", objid, db.database);
    if inspect {
        eprintln!("Inspection complete. No DBCC PAGE or changes made.");
        return Ok(());
    }
    // Resolve sysobjvalues allocation dynamically rather than reusing a hard-coded HoBT id.
    let alloc_sql = "SET NOCOUNT ON; SELECT 'RESULT|' + CONVERT(varchar(12),a.root_page,2) + '|' + CONVERT(varchar(12),a.first_page,2) FROM sys.system_internals_allocation_units a JOIN sys.partitions p ON a.container_id=p.hobt_id WHERE p.object_id=60 AND p.index_id=1 AND a.type=1;";
    let alloc = parse_sqlcmd_marker(&db.query(alloc_sql)?)?;
    if alloc.len() != 2 { return Err("unexpected allocation unit metadata".into()); }
    let root = parse_ptr(&hex_from_sql(&alloc[0])?)?;
    let rows = image_rows(&mut db, root, objid)?;
    let mut completed = Vec::new();
    for row in rows {
        if row.colid < 0 || row.colid > u16::MAX as i32 { return Err(format!("unsupported subobjid {}", row.colid)); }
        let cipher = assemble_cipher(&mut db, &row)?;
        let text = decrypt_strict(&cipher, &guid, objid as u32, row.colid as u16, Some(name))?;
        completed.push((row.colid, text));
    }
    completed.sort_by_key(|(id, _)| *id);
    // A numbered procedure may have several independent definitions. Exporting one combined file would be misleading.
    if completed.len() != 1 { return Err(format!("{} definitions found; this version refuses to merge numbered procedures", completed.len())); }
    let sql_text = &completed[0].1;
    let destination = output.expect("checked above");
    secure_write(&destination, sql_text.as_bytes())?;
    eprintln!("OK: {} bytes of SQL written to {destination}; {} unique DBCC pages read", sql_text.len(), db.page_count);
    Ok(())
}

// Called by the Tauri desktop backend. The original algorithm and page parser above remain unchanged.
pub(crate) fn decrypt_to_file(
    server: &str, database: &str, user: &str, password: &str,
    procedure: &str, output: &str, max_pages: usize,
) -> Result<(), String> {
    remote_run(
        server.to_string(), database.to_string(), user.to_string(),
        procedure.to_string(), Some(output.to_string()), false, true,
        max_pages, password.to_string(),
    )
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return;
    }
    if args.iter().any(|a| a == "--server") {
        let mut server = None;
        let mut database = None;
        let mut user = None;
        let mut procedure = None;
        let mut output = None;
        let mut inspect = false;
        let mut allow_pages = false;
        let mut max_pages = 128usize;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut value = || it.next().cloned().unwrap_or_else(|| fail(&format!("{a} needs value")));
            match a.as_str() {
                "--server" => server = Some(value()),
                "--database" => database = Some(value()),
                "--user" => user = Some(value()),
                "--procedure" => procedure = Some(value()),
                "--output" => output = Some(value()),
                "--inspect" => inspect = true,
                "--allow-dbcc-page" => allow_pages = true,
                "--max-pages" => max_pages = value().parse().unwrap_or_else(|_| fail("invalid max-pages")),
                other => fail(&format!("unknown remote argument {other}")),
            }
        }
        remote_run(server.unwrap_or_else(||fail("--server required")),
            database.unwrap_or_else(|| fail("--database required")),
            user.unwrap_or_else(|| fail("--user required")),
            procedure.unwrap_or_else(|| fail("--procedure required")),
            output, inspect, allow_pages, max_pages,
            std::env::var("SQLCMDPASSWORD").unwrap_or_default())
            .unwrap_or_else(|err| fail(&err));
        return;
    }
    let mut guid = None;
    let mut object_id: Option<i64> = None;
    let mut number: i64 = 1;
    let mut hex = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().cloned().unwrap_or_else(|| fail(&format!("{a} needs value")));
        match a.as_str() {
            "--family-guid" => guid = Some(value()),
            "--object-id" => object_id = Some(value().parse().unwrap_or_else(|_| fail("--object-id must be integer"))),
            "--number" => number = value().parse().unwrap_or_else(|_| fail("--number must be integer")),
            "--hex" => hex = Some(value()),
            other => fail(&format!("unknown argument {other}")),
        }
    }
    let guid = guid.unwrap_or_else(|| fail("--family-guid is required"));
    let object_id = object_id.unwrap_or_else(|| fail("--object-id is required"));
    if !(0..=u32::MAX as i64).contains(&object_id) { fail("object-id out of range"); }
    if !(0..=u16::MAX as i64).contains(&number) { fail("number out of range"); }
    let hex = hex.unwrap_or_else(|| fail("--hex is required"));
    let hex_text = if hex == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).unwrap_or_else(|e| fail(&format!("cannot read stdin: {e}")));
        s
    } else { hex };
    let guid = guid_to_dotnet_bytes(&guid).unwrap_or_else(|e| fail(&e));
    let cipher = decode_hex(&hex_text).unwrap_or_else(|e| fail(&e));
    let src = decrypt_strict(&cipher, &guid, object_id as u32, number as u16, None).unwrap_or_else(|e| fail(&e));
    println!("{src}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn rc4_vectors() {
        assert_eq!(hex(&rc4(b"Plaintext", b"Key")), "bbf316e8d940af0ad3");
        assert_eq!(hex(&rc4(b"pedia", b"Wiki")), "1021bf0420");
    }

    #[test]
    fn guid_matches_dotnet_order() {
        let g = guid_to_dotnet_bytes("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert_eq!(hex(&g), "33221100554477668899aabbccddeeff");
        assert_eq!(g, guid_to_dotnet_bytes("{00112233-4455-6677-8899-AABBCCDDEEFF}").unwrap());
        assert!(guid_to_dotnet_bytes("not-a-guid").is_err());
    }

    #[test]
    fn hex_decoding() {
        assert_eq!(decode_hex("0xDEad beef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn round_trip_and_wrong_subobjid() {
        let g = guid_to_dotnet_bytes("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let src = "CREATE PROCEDURE dbo.demo AS SELECT N'halo dunia 😀' AS x;";
        let units: Vec<u8> = src.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let ct = rc4(&units, &derive_key(&g, 123_456_789, 1));
        assert_eq!(decrypt(&ct, &g, 123_456_789, 1), src);
        assert_ne!(decrypt(&ct, &g, 123_456_789, 2), src);
    }
    #[test]
    fn parse_index_page_pointer() {
        let bytes = [0x34, 0x12, 0, 0, 0x02, 0];
        assert_eq!(parse_ptr(&bytes).unwrap(), PageRef { file: 2, page: 4660 });
        assert!(parse_ptr(&[0; 6]).is_err());
    }

    #[test]
    fn strict_rejects_non_utf16_ciphertext() {
        let guid = guid_to_dotnet_bytes("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        assert!(decrypt_strict(&[], &guid, 1, 1, None).is_err());
        assert!(decrypt_strict(&[1], &guid, 1, 1, None).is_err());
    }

    #[test]
    fn parse_dbcc_dump_complete() {
        let mut page = vec![0u8; PAGE_SIZE];
        page[1] = 2;
        page[23] = 0;
        let mut text = String::from("PAGE HEADER:|PAGE HEADER:|m_pageId|(1:123)\n");
        for i in (0..PAGE_SIZE).step_by(16) {
            text.push_str(&format!("whatever|Memory Dump @0x1000|dump|{:016X}: ", 0x1000 + i));
            for j in (i..i + 16).step_by(4) {
                text.push_str(&format!("{:02X}{:02X}{:02X}{:02X} ", page[j], page[j+1], page[j+2], page[j+3]));
            }
            text.push_str(" ....\n");
        }
        let result = dump_from_dbcc(&text, PageRef {file:1,page:123}).unwrap();
        assert_eq!(result, page);
        assert!(dump_from_dbcc(&text, PageRef {file:1,page:124}).is_err());
    }

}
