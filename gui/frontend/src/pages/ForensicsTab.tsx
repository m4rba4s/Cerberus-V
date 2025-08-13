import React, { useEffect, useRef, useState } from 'react';
import { Box, Chip, CircularProgress, Paper, Typography, Button, Dialog, DialogTitle, DialogContent, DialogActions, Grid, TextField } from '@mui/material';

interface SysEvent {
  ts: string;
  process: string;
  syscall: string;
  pid?: number;
}

const Forensics: React.FC = () => {
  const [events, setEvents] = useState<SysEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [procDetails, setProcDetails] = useState<any>(null);
  const [actMsg, setActMsg] = useState<string | null>(null);
  const [query, setQuery] = useState<string>('');
  const [polling, setPolling] = useState<boolean>(true);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const listRef = useRef<HTMLDivElement | null>(null);

  const fmtPct = (v: any): string => {
    const n = Number(v);
    return Number.isFinite(n) ? n.toFixed(1) : '0.0';
  };

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      try {
        const res = await fetch('/api/obs/syscalls', { signal: controller.signal });
        if (!res.ok) throw new Error('syscalls fetch failed');
        const data = await res.json();
        setEvents(data?.events || []);
        setError(null);
      } catch (e) {
        if ((e as any)?.name !== 'AbortError') setError('failed');
      } finally {
        setLoading(false);
      }
    };
    // Initial load
    load();
    // Poll only when enabled
    let id: any;
    if (polling) {
      id = setInterval(load, 8000);
    }
    return () => { controller.abort(); if (id) clearInterval(id); };
  }, [polling]);

  // Auto-scroll to bottom on update
  useEffect(() => {
    if (!autoScroll) return;
    const el = listRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
  }, [events, autoScroll]);

  const exportCsv = () => {
    const filtered = events.filter(e => {
      if (!query) return true;
      const q = query.toLowerCase();
      return (e.process||'').toLowerCase().includes(q) || (e.syscall||'').toLowerCase().includes(q) || String(e.pid||'').includes(q);
    });
    const rows = [
      ['ts','pid','process','syscall'],
      ...filtered.map(e => [e.ts, String(e.pid ?? ''), e.process ?? '', e.syscall ?? ''])
    ];
    const csv = rows.map(r => r.map(v => '"' + String(v).replace(/"/g,'""') + '"').join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `syscalls_${new Date().toISOString().replace(/[:.]/g,'-')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) return (
    <Box sx={{ display:'flex', alignItems:'center', gap:2 }}>
      <CircularProgress size={24} />
      <Typography>Loading syscalls…</Typography>
    </Box>
  );

  if (error) return (
    <Typography color="warning.main">Using demo forensic data</Typography>
  );

  return (
    <Paper sx={{ p:2 }}>
      <Box sx={{ display:'flex', alignItems:'center', justifyContent:'space-between', mb:1 }}>
        <Typography variant="subtitle1">Recent Syscalls</Typography>
        <Box sx={{ display:'flex', gap:1 }}>
          <TextField
            size="small"
            placeholder="Filter (syscall or process)"
            value={query}
            onChange={(e)=>setQuery(e.target.value)}
          />
          <Button variant="outlined" onClick={()=>setQuery('')}>Clear</Button>
          <Button variant="outlined" color={polling ? 'warning' : 'success'} onClick={()=>setPolling(v=>!v)}>
            {polling ? 'Pause' : 'Resume'}
          </Button>
          <Button variant="outlined" onClick={()=>setAutoScroll(v=>!v)}>
            {autoScroll ? 'Auto-Scroll: On' : 'Auto-Scroll: Off'}
          </Button>
          <Button variant="contained" onClick={exportCsv}>Export CSV</Button>
        </Box>
      </Box>
      <Box ref={listRef} sx={{ display:'flex', flexDirection:'column', gap:1, maxHeight:360, overflow:'auto' }}>
        {events.filter(e => {
            if (!query) return true;
            const q = query.toLowerCase();
            return (e.process||'').toLowerCase().includes(q) || (e.syscall||'').toLowerCase().includes(q) || String(e.pid||'').includes(q);
          }).slice(0,50).map((e, idx) => (
          <Box key={idx} sx={{ display:'flex', gap:1, alignItems:'center' }}>
            <Chip label={new Date(e.ts).toLocaleTimeString()} size="small" />
            <Typography sx={{ fontFamily:'monospace' }}>{e.process}({e.pid ?? '-'})</Typography>
            <Chip label={e.syscall} size="small" color="info" />
            {!!e.pid && <Button size="small" onClick={async ()=>{
              setSelectedPid(e.pid!);
              try{ const r = await fetch(`/api/obs/process/${e.pid}`); if(r.ok){ const j=await r.json(); setProcDetails(j.process);} }catch{}
            }}>Details</Button>}
          </Box>
        ))}
      </Box>

      <Dialog open={!!selectedPid} onClose={()=>{setSelectedPid(null); setProcDetails(null); setActMsg(null);}} maxWidth="md" fullWidth>
        <DialogTitle>Process Details {selectedPid!=null && `PID ${selectedPid}`}</DialogTitle>
        <DialogContent>
          {procDetails ? (
            <Grid container spacing={2}>
              <Grid item xs={12}><Typography variant="body2">Name: {procDetails.name || '?'}</Typography></Grid>
              <Grid item xs={12}><Typography variant="body2">User: {procDetails.username || '?'}</Typography></Grid>
              <Grid item xs={12}><Typography variant="body2">Cmd: {(procDetails.cmdline||[]).join(' ')}</Typography></Grid>
              <Grid item xs={12}><Typography variant="body2">CPU: {fmtPct(procDetails.cpu_percent)}% MEM: {fmtPct(procDetails.memory_percent)}%</Typography></Grid>
              {actMsg && <Grid item xs={12}><Typography color="success.main">{actMsg}</Typography></Grid>}
            </Grid>
          ) : (<Typography variant="body2">Loading…</Typography>)}
        </DialogContent>
        <DialogActions>
          <Button onClick={()=>setSelectedPid(null)}>Close</Button>
          {selectedPid!=null && (
            <Box sx={{ display:'flex', gap:1 }}>
              {['terminate','kill','stop','cont'].map(a => (
                <Button key={a} color={a==='kill'?'error':a==='terminate'?'warning':'primary'} onClick={async()=>{
                  try{ const r=await fetch(`/api/obs/process/${selectedPid}/${a}`,{method:'POST'}); const j=await r.json(); setActMsg(j.message||j.detail||''); if(r.ok){ const rd=await fetch(`/api/obs/process/${selectedPid}`); if(rd.ok){ const jj=await rd.json(); setProcDetails(jj.process);} } }catch{}
                }}>{a}</Button>
              ))}
              <Button onClick={async()=>{ try{ const r=await fetch(`/api/obs/process/${selectedPid}/renice?value=10`,{method:'POST'}); const j=await r.json(); setActMsg(j.message||j.detail||''); }catch{} }}>renice +10</Button>
            </Box>
          )}
        </DialogActions>
      </Dialog>
    </Paper>
  );
}

export default Forensics;


