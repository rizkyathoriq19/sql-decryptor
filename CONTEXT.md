# SQL Decryptor

Read-only inspection of SQL Server stored procedures created `WITH ENCRYPTION`.

## Language

**Connection**:
A SQL Server login (server, database, username, password) used through `sqlcmd`.
_Avoid_: session, profile

**Procedure**:
A user-defined stored procedure, always named `schema.name`.
_Avoid_: SP, object, module

**Encrypted Procedure**:
A **Procedure** whose `IsEncrypted` property is 1; the only kind that can be decrypted.

**Decryption**:
Recovering one **Encrypted Procedure**'s source by reading its ciphertext with `DBCC PAGE` and applying SHA-1/RC4. Never executes or alters the source.
_Avoid_: extraction, dump

**Page Cap**:
The maximum number of unique `DBCC PAGE` reads one **Decryption** may perform; default 32, hard maximum 256.
_Avoid_: max pages, limit

**Risk Acknowledgment**:
An explicit human confirmation that undocumented `DBCC PAGE` reads may load the server. In the desktop app it is given before every **Decryption**; for the **Decryptor MCP Server** it is given once, by a human, in that server's configuration.
_Avoid_: acknowledge_risk argument

**Decryptor MCP Server**:
A local process that lets an AI agent list databases and **Procedures** and perform **Decryptions** without the desktop app. It uses one fixed **Connection** set by a human and never sees the password in tool calls.
_Avoid_: plugin, bridge

**Export**:
Saving decrypted source to a new `.sql` file; never overwrites an existing file.
