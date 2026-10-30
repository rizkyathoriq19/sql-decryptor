# SQL Decryptor — Tauri 2 + React + IBM Carbon MVP

Desktop MVP untuk **connect → browse procedures → decrypt → export**. UI dibangun dengan React/TypeScript, IBM Carbon, dan Tauri 2; backend menggunakan **engine `sqltextdecrypt_remote.rs` milik pengguna** yang disalin sebagai `src-tauri/src/engine.rs` lalu diadaptasi supaya dipanggil secara langsung sebagai modul Rust.

> **Status:** source project selesai disusun. Verifikasi source-level di Linux/Omarchy: `npm run build` (tsc + Vite) lulus, `cargo check` 0 error, dan 8 unit test engine lulus. **Build bundle Tauri lengkap, integrasi GUI nyata, dan SQL Server live belum diverifikasi**; uji dengan database hasil restore dan izin DBA terlebih dahulu.

## Fitur

1. **Connect**: koneksi nyata ke SQL Server memakai `sqlcmd` yang sudah terpasang. Mendapatkan `DB_NAME()`, `ProductVersion`, serta role sysadmin.
2. **Browse**: membaca `sys.procedures` (maks. 1.000 record), filter nama, dan deteksi status `IsEncrypted`.
3. **Decrypt**: memakai SHA-1/RC4/UTF-16LE dan ekstraksi ciphertext via bounded `DBCC PAGE` dari source engine yang sudah ada. Dibatasi **32 halaman unik**, hanya satu proses dekripsi sekaligus, perlu checkbox persetujuan setiap operasi. Output diperiksa ketat sebelum ditampilkan.
4. **Export**: sistem dialog native untuk menyimpan `.sql`, **tidak menimpa file yang sudah ada**.

Semua source SQL yang terlihat di preview ditampilkan sebagai teks saja. **Tidak ada fitur untuk mengeksekusi source SQL atau mengubah stored procedure.**

## Struktur penting

```
src/App.tsx                 Interface Carbon dan alur pengguna
src/styles.scss             Styling desktop enterprise
src-tauri/src/lib.rs        Tauri commands, koneksi sqlcmd, listing, export
src-tauri/src/engine.rs     Reused Rust decryptor (original algorithm + modified integration)
src-tauri/tauri.conf.json   Desktop configuration
src-tauri/capabilities/     Native dialog permission
```

## Persiapan di Omarchy (Arch Linux)

Tauri v2 membutuhkan Rust terbaru dan WebKitGTK 4.1. Instal dependensi jika belum ada:

```bash
sudo pacman -S --needed \
  webkit2gtk-4.1 base-devel curl wget file openssl \
  appmenu-gtk-module libappindicator-gtk3 librsvg xdotool
```

Tauri plugin dialog terbaru memerlukan Rust >= 1.90. Update versi stable menggunakan `rustup update stable` jika perlu.

```bash
rustc --version
cargo --version
node --version
sqlcmd --help
```

**Pastikan `sqlcmd` tersedia di `PATH` terminal tempat aplikasi dijalankan.** Jika binary `sqlcmd` berada di `~/.local/bin`:

```bash
export PATH="$HOME/.local/bin:$PATH"
command -v sqlcmd
```

Saat membuka app lewat desktop launcher, PATH mungkin berbeda dari terminal; pada tahap awal jalankan dari terminal.

## Menjalankan aplikasi

Ekstrak ZIP, masuk ke folder proyek, lalu:

```bash
npm install
npm run desktop
```

Perintah tersebut menjalankan Vite dan Tauri dalam mode pengembangan. Tauri CLI akan mengunduh dan mengompilasi dependensi Rust saat dijalankan pertama kali. Build distribusi:

```bash
npm run desktop:build
```

Bila butuh debug frontend saja, `npm run dev` akan membuka halaman HTML, tetapi **fitur connect/decrypt/export tidak tersedia** di browser biasa karena membutuhkan runtime Tauri.

### Test engine Rust secara terpisah

```bash
rustc --edition=2021 --test src-tauri/src/engine.rs -o /tmp/sql_decryptor_tests
/tmp/sql_decryptor_tests
```

Delapan unit test engine lulus (SHA-1, RC4, GUID .NET, hex, round-trip, index pointer, strict UTF-16, dan parser DBCC). Tes ini **bukan** pembuktian bahwa ekstraksi akan berhasil pada semua versi SQL Server.

## Penggunaan

Buka aplikasi, isi Server (`10.0.2.7`), Database (`PTTTI`), Username (`sa`), dan password (tidak disimpan). Tekan **Connect**, pilih prosedur terenkripsi, lalu **Decrypt**. Dialog meminta persetujuan sebelum operasi `DBCC PAGE`. Setelah muncul source, tekan **Export .sql** untuk memilih lokasi penyimpanan. File SQL untuk analisis saja, **jangan dieksekusi ke production**.

## Batasan dan keamanan

- Koneksi SQL Server menggunakan `sqlcmd` sebagai child process, bukan PowerShell. Input server/database/user dibatasi; query metadata yang dibangun aplikasi bersifat tetap.
- Password hanya ada di memori frontend selama sesi, disalurkan ke Tauri IPC, lalu diteruskan ke **environment child process sqlcmd**. Tidak dikirim melalui argument `-P`, disimpan ke file konfigurasi, atau dicatat pada log. Mengosongkan field atau menutup aplikasi menghilangkan nilai pada proses tersebut.
- Engine **tidak sengaja menulis ke database** (tidak memakai DDL/DML). Namun `DBCC PAGE` adalah operasi internal undocumented dan dapat menggunakan resource server. **Tidak ada jaminan bebas downtime**. Uji pada database hasil restore dan dapatkan izin DBA sebelum memakai production.
- `max_pages` untuk GUI dipatok ke 32. Jika terlalu kecil untuk prosedur besar, proses akan menolak, bukan otomatis menaikkannya. Parser halaman dan LOB internal SQL Server perlu validasi lintas versi.
- GUI tidak otomatis membuka koneksi pada saat aplikasi startup. Hanya pemilihan prosedur terenkripsi yang bisa meminta dekripsi.
- `src-tauri/src/engine.rs` masih menggunakan pemetaan indeks internal `sysobjvalues` (`object_id=60`, `index_id=1`) berdasarkan metadata server SQL Server 2019 yang sudah diperiksa; ini tidak dijamin berlaku di server SQL Server lain.
- Daftar prosedur dibatasi 1.000 hasil; tidak ada pagination atau data table editor pada MVP.
- Export memakai exclusive `create_new`; jika file sudah ada, pilih nama berbeda.
- Proyek ini tidak menyertakan credential, ciphertext, source eConnect hasil dekripsi, atau akses ke server.

## Implementasi engine asli

Source `src-tauri/src/engine.rs` berasal dari file `sqltextdecrypt_remote.rs` yang disediakan sebelumnya. Bagian SHA-1, RC4, GUID `.NET` little-endian, decoder dan parser `DBCC PAGE` dipertahankan. Adaptasi minimal untuk GUI:

- menerima password pada argumen fungsi internal (bukan environment global);
- memberikan password hanya ke proses `sqlcmd` yang dipanggil Rust;
- menambahkan fungsi `decrypt_to_file` yang dipanggil Tauri;
- tidak memakai allocation ID literal: lookup allocation IN_ROW `sysobjvalues` dilakukan per database;
- sumber sementara terenkripsi disimpan ke direktori sementara OS, dibaca, lalu direktori dihapus otomatis.

## Dokumentasi rujukan

- Tauri 2: https://v2.tauri.app/start/prerequisites/
- Tauri 2 commands: https://v2.tauri.app/develop/calling-rust/
- Tauri native save dialog: https://v2.tauri.app/plugin/dialog/
- IBM Carbon React: https://github.com/carbon-design-system/carbon/tree/main/packages/react

**MVP source-level, belum diverifikasi end-to-end pada SQL Server.**
