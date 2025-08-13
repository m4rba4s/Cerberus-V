// SPDX-License-Identifier: Apache-2.0
// Live Syscalls & Logs viewer (MVP; backend must expose endpoints)

import React, { useEffect, useState } from 'react';
import { Box, Card, CardHeader, CardContent, Typography, Grid, Chip, TextField, Button, List, ListItem, ListItemText } from '@mui/material';

interface SysEvent { ts: string; pid: number; comm: string; syscall: string; args?: string; }
interface LogLine { ts: string; level: string; msg: string; }

const SystemCalls: React.FC = () => {
  const [events, setEvents] = useState<SysEvent[]>([]);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    let alive = true;
    const pull = async () => {
      try {
        const [e, l] = await Promise.all([
          fetch('/api/obs/syscalls'),
          fetch('/api/logs'),
        ]);
        if (!alive) return;
        if (e.ok) {
          const ej = await e.json();
          setEvents((ej.events || []).slice(0, 200));
        }
        if (l.ok) {
          const lj = await l.json();
          const raw = (lj.logs || []) as string[];
          setLogs(raw.slice(-200).map((s) => ({ ts: s.slice(1, 20), level: s.includes('ERROR') ? 'error' : 'info', msg: s })));
        }
      } catch {}
    };
    pull();
    const id = setInterval(pull, 2000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const visible = events.filter(e => !filter || e.syscall.includes(filter) || e.comm.includes(filter));

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2, fontWeight: 'bold' }}>🔍 Active Logs & Syscalls</Typography>
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader title="Syscalls (recent)" action={<Chip label={`${visible.length}`} color="primary" />} />
            <CardContent>
              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                <TextField size="small" label="Filter (syscall or comm)" value={filter} onChange={(e) => setFilter(e.target.value)} />
                <Button variant="outlined" onClick={() => setFilter('')}>Clear</Button>
              </Box>
              <List dense sx={{ maxHeight: 420, overflow: 'auto' }}>
                {visible.map((e, idx) => (
                  <ListItem key={idx} divider>
                    <ListItemText primary={`${e.ts}  ${e.comm}[${e.pid}] → ${e.syscall}`} secondary={e.args} />
                  </ListItem>
                ))}
                {visible.length === 0 && <Typography variant="body2" color="text.secondary">No syscall events</Typography>}
              </List>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader title="System Logs (tail)" />
            <CardContent>
              <List dense sx={{ maxHeight: 480, overflow: 'auto' }}>
                {logs.map((l, idx) => (
                  <ListItem key={idx} divider>
                    <ListItemText primary={l.msg} />
                  </ListItem>
                ))}
                {logs.length === 0 && <Typography variant="body2" color="text.secondary">No logs</Typography>}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default SystemCalls;


