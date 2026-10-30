import { useEffect, useMemo, useState } from 'react';
import {
  Button, Checkbox, InlineLoading, InlineNotification, Modal, PasswordInput,
  Search, Tag, TextInput,
} from '@carbon/react';
import {
  DataBase, Download, Renew, Locked, Unlocked, Code, ChevronRight,
  Connect, WarningAlt, Document,
} from '@carbon/icons-react';
import { invoke } from '@tauri-apps/api/core';
import { save } from '@tauri-apps/plugin-dialog';

type Conn = { server: string; database: string; username: string; password: string };
type ServerInfo = { database: string; productVersion: string; isSysadmin: boolean };
type Proc = { schema: string; name: string; objectId: number; encrypted: boolean };
type Decrypted = { procedure: string; source: string; bytes: number; note: string };
type Alert = { kind: 'error' | 'success' | 'warning' | 'info'; title: string; message: string };
type Work = 'connect' | 'browse' | 'decrypt' | 'export' | null;

const START: Conn = { server: '', database: '', username: '', password: '' };

function highlighted(text: string) {
  const chunks = text.split(/(--[^\n]*|'(?:''|[^'])*'|\b(?:CREATE|ALTER|PROCEDURE|PROC|BEGIN|END|SET|AS|SELECT|FROM|WHERE|JOIN|ON|DECLARE|EXEC|EXECUTE|INSERT|INTO|UPDATE|DELETE|IF|ELSE|RETURN|OUTPUT|CASE|WHEN|THEN|AND|OR|NOT|NULL|IS|TRY|CATCH|TRANSACTION|COMMIT|ROLLBACK|RAISERROR|INT|VARCHAR|NVARCHAR|DATETIME|NUMERIC|BIT|GO)\b)/gi);
  return chunks.map((fragment, idx) => {
    let category = '';
    if (fragment.startsWith('--')) category = 'sql-comment';
    else if (fragment.startsWith("'")) category = 'sql-string';
    else if (/^(CREATE|ALTER|PROCEDURE|PROC|BEGIN|END|SET|AS|SELECT|FROM|WHERE|JOIN|ON|DECLARE|EXEC|EXECUTE|INSERT|INTO|UPDATE|DELETE|IF|ELSE|RETURN|OUTPUT|CASE|WHEN|THEN|AND|OR|NOT|NULL|IS|TRY|CATCH|TRANSACTION|COMMIT|ROLLBACK|RAISERROR|INT|VARCHAR|NVARCHAR|DATETIME|NUMERIC|BIT|GO)$/i.test(fragment)) category = 'sql-keyword';
    return <span className={category} key={idx}>{fragment}</span>;
  });
}

export default function App() {
  const [config, setConfig] = useState<Conn>(START);
  const [info, setInfo] = useState<ServerInfo | null>(null);
  const [procedures, setProcedures] = useState<Proc[]>([]);
  const [selected, setSelected] = useState<Proc | null>(null);
  const [result, setResult] = useState<Decrypted | null>(null);
  const [search, setSearch] = useState('');
  const [onlyEncrypted, setOnlyEncrypted] = useState(false);
  const [busy, setBusy] = useState<Work>(null);
  const [alert, setAlert] = useState<Alert | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [riskAcknowledged, setRiskAcknowledged] = useState(false);
  const [sqlcmdReady, setSqlcmdReady] = useState<boolean | null>(null);
  const [checkingSqlcmd, setCheckingSqlcmd] = useState(false);

  const visible = useMemo(() => procedures.filter(p =>
    (!onlyEncrypted || p.encrypted) && `${p.schema}.${p.name}`.toLowerCase().includes(search.toLowerCase())
  ), [procedures, onlyEncrypted, search]);
  const encryptedCount = procedures.filter(p => p.encrypted).length;
  const shown = result && selected && result.procedure === `${selected.schema}.${selected.name}` ? result : null;
  const isBusy = busy !== null;

  async function checkSqlcmd() {
    setCheckingSqlcmd(true);
    try { setSqlcmdReady(await invoke<boolean>('check_sqlcmd')); }
    catch { setSqlcmdReady(false); }
    finally { setCheckingSqlcmd(false); }
  }

  useEffect(() => { void checkSqlcmd(); }, []);

  function updateConfig(field: keyof Conn, value: string) {
    setConfig(v => ({ ...v, [field]: value }));
    setInfo(null); setProcedures([]); setSelected(null); setResult(null); setAlert(null);
  }

  function showError(error: unknown) {
    setAlert({ kind: 'error', title: 'Operation failed', message: String(error) });
  }

  async function connect() {
    if (!config.server || !config.database || !config.username || !config.password) {
      showError('Server, database, username, and password are required.'); return;
    }
    setAlert(null); setBusy('connect'); setResult(null);
    try {
      const data = await invoke<ServerInfo>('connect_database', { config });
      setInfo(data);
      setBusy('browse');
      try {
        const items = await invoke<Proc[]>('browse_procedures', { config });
        setProcedures(items);
        setSelected(items[0] || null);
        setAlert({ kind: 'success', title: 'Connected', message: `Connected to ${data.database}. Loaded ${items.length} procedures.` });
      } catch (e) { showError(e); }
    } catch (e) { setInfo(null); showError(e); }
    finally { setBusy(null); }
  }

  async function refresh() {
    if (!info) return;
    setBusy('browse'); setAlert(null);
    try {
      const items = await invoke<Proc[]>('browse_procedures', { config });
      setProcedures(items);
      setSelected(old => items.find(p => p.schema === old?.schema && p.name === old?.name) || items[0] || null);
      setAlert({ kind: 'info', title: 'Refreshed', message: `Loaded ${items.length} procedures (first 1,000 maximum).` });
    } catch(e) { showError(e); }
    finally { setBusy(null); }
  }

  async function decrypt() {
    if (!selected || !info || !selected.encrypted || !riskAcknowledged) return;
    setConfirmOpen(false); setAlert(null); setBusy('decrypt');
    setResult(null);
    try {
      const data = await invoke<Decrypted>('decrypt_procedure', {
        config, procedure: `${selected.schema}.${selected.name}`, acknowledgeRisk: true,
      });
      setResult(data);
      setAlert({ kind: 'success', title: 'Decryption complete', message: `Validated ${data.bytes.toLocaleString()} UTF-8 bytes. Review the source before exporting.` });
    } catch (e) { showError(e); }
    finally { setBusy(null); setRiskAcknowledged(false); }
  }

  async function exportFile() {
    if (!shown) return;
    setBusy('export'); setAlert(null);
    try {
      const filename = `${shown.procedure.replace(/[^a-zA-Z0-9_-]/g, '_')}.sql`;
      const path = await save({ defaultPath: filename, filters: [{ name: 'SQL source', extensions: ['sql'] }] });
      if (!path) return;
      const saved = await invoke<string>('export_sql', { path, content: shown.source });
      setAlert({ kind: 'success', title: 'Exported', message: `Saved to ${saved}. Existing files are never overwritten.` });
    } catch (e) { showError(e); }
    finally { setBusy(null); }
  }

  function selectProcedure(proc: Proc) {
    setSelected(proc); setResult(null); setAlert(null);
  }

  const preview = shown?.source.slice(0, 160_000) ?? '';
  const lineCount = preview ? preview.split('\n').length : 0;

  return <div className="shell">
    <header className="topbar">
      <div className="top-brand"><div className="brand-mark"><DataBase size={19}/></div><div><strong>SQL Decryptor</strong><small>Developer tools / v0.1.0</small></div></div>
      <div className="top-status"><span className={`status-dot ${info ? 'online' : ''}`}/><span>{info ? `Connected to ${config.server}` : 'Not connected'}</span><span className="top-divider"/><span>Read-only metadata · guarded extraction</span></div>
    </header>
    {sqlcmdReady === false && (
      <div className="tool-warning" role="alert">
        <WarningAlt size={17}/>
        <div className="tool-warning-copy">
          <strong>sqlcmd not found</strong>
          <p>This app needs the SQL Server command-line tools. Install <code>sqlcmd</code> and make sure it is on this app's PATH, then check again. Restart the app after changing PATH.</p>
        </div>
        <Button size="sm" kind="ghost" disabled={checkingSqlcmd} onClick={checkSqlcmd}>{checkingSqlcmd ? 'Checking...' : 'Check again'}</Button>
      </div>
    )}
    <main className="app-layout">
      <aside className="connection-pane">
        <div className="pane-heading"><span className="eyebrow">WORKSPACE</span><h2>Connection</h2><p>Connect to a SQL Server instance to browse encrypted modules.</p></div>
        <div className="connection-fields">
          <TextInput id="host" labelText="Server" value={config.server} disabled={isBusy} onChange={e => updateConfig('server',e.target.value)}/>
          <TextInput id="database" labelText="DataBase" value={config.database} disabled={isBusy} onChange={e => updateConfig('database',e.target.value)}/>
          <TextInput id="username" labelText="Username" value={config.username} disabled={isBusy} onChange={e => updateConfig('username',e.target.value)}/>
          <PasswordInput id="pwd" labelText="Password" value={config.password} placeholder="Enter SQL password" disabled={isBusy} onChange={e => updateConfig('password',e.target.value)}/>
          <Button className="connect-btn" disabled={isBusy || !config.server || !config.database || !config.username || !config.password} onClick={connect} renderIcon={Connect}>{info ? 'Reconnect' : 'Connect to server'}</Button>
          {busy === 'connect' && <InlineLoading description="Connecting to SQL Server..."/>}
          {info && <div className="connected-summary"><span className="summary-title">ACTIVE CONNECTION</span><div><span>DataBase</span><strong>{info.database}</strong></div><div><span>SQL Server</span><strong>{info.productVersion}</strong></div><div><span>Admin access</span><Tag type={info.isSysadmin ? 'green':'warm-gray'}>{info.isSysadmin?'Yes':'No'}</Tag></div></div>}
        </div>
        <div className="aside-safety"><WarningAlt size={17}/><div><strong>Protected production workflow</strong><p>Browsing reads metadata only. Decrypt uses experimental internal page reads and requires confirmation each time.</p></div></div>
      </aside>
      <section className="browser-pane">
        <div className="browser-header"><div><span className="eyebrow">DATABASE EXPLORER</span><h2>Stored procedures</h2></div><Button kind="ghost" size="sm" hasIconOnly iconDescription="Refresh procedures" disabled={!info || isBusy} renderIcon={Renew} onClick={refresh}/></div>
        <div className="browser-tools">
          <Search size="md" id="procedure-search" labelText="Search procedures" placeholder="Search procedures" value={search} onChange={e => setSearch(e.target.value)}/>
          <div className="filter-line"><Checkbox id="encrypted-only" labelText="Encrypted only" checked={onlyEncrypted} onChange={(_evt, { checked }) => setOnlyEncrypted(checked)}/></div>
        </div>
        <div className="browser-stats"><span>{visible.length} shown</span><Tag type="blue">{encryptedCount} encrypted</Tag></div>
        <div className="object-list">
          {procedures.length === 0 && <div className="empty-procedures"><DataBase size={28}/><p>{info ? 'No procedures found' : 'Connect to browse database objects'}</p></div>}
          {visible.map(p => <button key={`${p.schema}.${p.name}`} type="button" className={`proc-item ${selected?.objectId === p.objectId ? 'active':''}`} onClick={() => selectProcedure(p)}><span className="proc-icon">{p.encrypted ? <Locked size={16}/> : <Unlocked size={16}/>}</span><span className="proc-name"><strong title={`${p.schema}.${p.name}`}>{p.name}</strong><small>{p.schema} · ID {p.objectId}</small></span><ChevronRight size={14}/></button>)}
          {procedures.length > 0 && visible.length === 0 && <div className="empty-procedures"><p>No matching procedures</p></div>}
        </div>
        <div className="browser-bottom">Showing up to 1,000 procedures per database</div>
      </section>
      <section className="editor-pane">
        <div className="editor-top"><div className="editor-title"><span className="eyebrow">SOURCE INSPECTOR</span><h1>{selected ? selected.name : 'Select a stored procedure'}</h1><div className="metadata">{selected && <><span>{selected.schema}</span><span className="metadata-sep">/</span><span>Object ID {selected.objectId}</span><Tag type={selected.encrypted ? 'purple' : 'gray'}>{selected.encrypted ? 'Encrypted':'Plaintext'}</Tag></>}</div></div>
          <div className="editor-actions"><Button size="sm" kind="secondary" renderIcon={Download} disabled={!shown || isBusy} onClick={exportFile}>Export .sql</Button><Button size="sm" renderIcon={Code} disabled={!selected?.encrypted || !info || isBusy} onClick={() => { setRiskAcknowledged(false); setConfirmOpen(true); }}>Decrypt</Button></div>
        </div>
        {alert && <div className="alert"><InlineNotification kind={alert.kind} title={alert.title} subtitle={alert.message} lowContrast onCloseButtonClick={() => setAlert(null)}/></div>}
        {busy === 'decrypt' && <div className="loading"><InlineLoading description="Decrypting with bounded DBCC PAGE reads..."/></div>}
        <div className="code-toolbar"><div><Document size={16}/><span>{shown ? `${shown.procedure}.sql` : 'SQL preview'}</span></div><span>{shown ? `${shown.bytes.toLocaleString()} bytes · UTF-8` : 'No source loaded'}</span></div>
        <div className="editor-area">
          {shown ? <div className="code-view"><div className="line-numbers" aria-hidden="true">{Array.from({length: lineCount},(_,i) => <span key={i}>{i+1}</span>)}</div><pre><code>{highlighted(preview)}{shown.source.length > preview.length ? '\n-- Preview truncated. Export saves the complete SQL file.' : ''}</code></pre></div>
          : <div className="editor-empty"><div className="empty-icon"><Code size={32}/></div><h3>SQL source preview</h3><p>{selected?.encrypted ? 'Decrypt the selected procedure to inspect its source code.' : selected ? 'This module is not encrypted. MVP decrypt is available for encrypted procedures only.' : 'Select an encrypted procedure in the explorer to get started.'}</p><div className="empty-hint"><span className="step-circle">1</span> Connect <ChevronRight size={13}/><span className="step-circle">2</span> Browse <ChevronRight size={13}/><span className="step-circle">3</span> Decrypt <ChevronRight size={13}/><span className="step-circle">4</span> Export</div></div>}
        </div>
        <footer className="editor-footer"><span>{shown ? 'Validation passed · Not executed in SQL Server' : 'SQL scripts are never executed by this app'}</span><span>SQL Decryptor v0.1.0</span></footer>
      </section>
    </main>
    <Modal open={confirmOpen} danger modalHeading="Decrypt encrypted stored procedure?" primaryButtonText="I understand — decrypt" secondaryButtonText="Cancel" primaryButtonDisabled={!riskAcknowledged} onRequestSubmit={decrypt} onRequestClose={() => setConfirmOpen(false)}>
      <p className="risk-lead"><strong>{selected ? `${selected.schema}.${selected.name}` : ''}</strong> on <strong>{config.server}/{config.database}</strong></p>
      <p>The operation reads SQL Server internal pages using <strong>DBCC PAGE</strong>. It does not intentionally modify database objects, but is experimental and can consume server I/O. Server availability cannot be guaranteed.</p>
      <p>The engine limits unique page reads to <strong>32</strong>. Use a restored database for first testing; only use a production server with DBA authorization.</p>
      <div className="modal-check"><Checkbox id="risk-confirm" labelText="I am authorized to inspect this database and accept the operational risk." checked={riskAcknowledged} onChange={(_evt, { checked }) => setRiskAcknowledged(checked)}/></div>
    </Modal>
  </div>;
}
