import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  Alert,
  AlertTitle,
  Grid,
  CircularProgress
} from '@mui/material';
import {
  PlayArrow,
  Stop,
  Refresh,
  Security,
  Memory,
  Speed,
  Warning
} from '@mui/icons-material';

interface EbpfProgram {
  name: string;
  type: string;
  status: string;
  interface: string;
}

interface EbpfStats {
  packets_processed: number;
  packets_dropped: number;
  bytes_processed: number;
  cpu_usage: number;
}

interface SystemStatus {
  running: boolean;
  active_programs: number;
  total_programs: number;
  programs: EbpfProgram[];
  stats: EbpfStats;
}

const EBPFControl: React.FC = () => {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchSystemStatus = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/system/status');
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();
      setSystemStatus(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch system status');
    } finally {
      setLoading(false);
    }
  };

  const startSystem = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/system/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      await fetchSystemStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start system');
    } finally {
      setLoading(false);
    }
  };

  const stopSystem = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/system/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      await fetchSystemStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to stop system');
    } finally {
      setLoading(false);
    }
  };

  const loadProgram = async (name: string, interfaceName: string) => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/ebpf/load', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, interface: interfaceName })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      await fetchSystemStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to load program ${name}`);
    } finally {
      setLoading(false);
    }
  };

  const unloadProgram = async (name: string) => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/ebpf/unload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      await fetchSystemStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to unload program ${name}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSystemStatus();
    const interval = setInterval(fetchSystemStatus, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success';
      case 'inactive': return 'default';
      case 'error': return 'error';
      default: return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <PlayArrow />;
      case 'inactive': return <Stop />;
      case 'error': return <Warning />;
      default: return <Stop />;
    }
  };

  if (loading && !systemStatus) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          <AlertTitle>Error</AlertTitle>
          {error}
        </Alert>
      )}

      {/* System Control */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6" component="h2">
              <Security sx={{ mr: 1, verticalAlign: 'middle' }} />
              Firewall Engine Control
            </Typography>
            <Box>
              <Button
                variant="contained"
                color="success"
                startIcon={<PlayArrow />}
                onClick={startSystem}
                disabled={loading || systemStatus?.running}
                sx={{ mr: 1 }}
              >
                Start System
              </Button>
              <Button
                variant="contained"
                color="error"
                startIcon={<Stop />}
                onClick={stopSystem}
                disabled={loading || !systemStatus?.running}
                sx={{ mr: 1 }}
              >
                Stop System
              </Button>
              <Tooltip title="Refresh Status">
                <IconButton onClick={fetchSystemStatus} disabled={loading}>
                  <Refresh />
                </IconButton>
              </Tooltip>
            </Box>
          </Box>

          {systemStatus && (
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Box textAlign="center">
                  <Typography variant="h4" color={systemStatus.running ? 'success.main' : 'error.main'}>
                    {systemStatus.running ? 'ACTIVE' : 'INACTIVE'}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    System Status
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box textAlign="center">
                  <Typography variant="h4">
                    {systemStatus.active_programs}/{systemStatus.total_programs}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Active Programs
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box textAlign="center">
                  <Typography variant="h4">
                    {(systemStatus.stats?.packets_processed || 0).toLocaleString()}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Packets Processed
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          )}
        </CardContent>
      </Card>

      {/* eBPF Programs Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" component="h2" mb={2}>
            <Memory sx={{ mr: 1, verticalAlign: 'middle' }} />
            eBPF Programs
          </Typography>
          
          {systemStatus && (
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Program</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Interface</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {systemStatus.programs.map((program) => (
                    <TableRow key={program.name}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {program.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={program.type} 
                          size="small" 
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>{program.interface}</TableCell>
                      <TableCell>
                        <Chip
                          icon={getStatusIcon(program.status)}
                          label={program.status}
                          color={getStatusColor(program.status) as any}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {program.status === 'active' ? (
                          <Button
                            size="small"
                            variant="outlined"
                            color="error"
                            onClick={() => unloadProgram(program.name)}
                            disabled={loading}
                          >
                            Unload
                          </Button>
                        ) : (
                          <Button
                            size="small"
                            variant="outlined"
                            color="success"
                            onClick={() => loadProgram(program.name, program.interface)}
                            disabled={loading}
                          >
                            Load
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </CardContent>
      </Card>

      {/* Statistics */}
      {systemStatus && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Typography variant="h6" component="h2" mb={2}>
              <Speed sx={{ mr: 1, verticalAlign: 'middle' }} />
              Performance Statistics
            </Typography>
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="primary.main">
                    {(systemStatus.stats?.packets_processed || 0).toLocaleString()}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Packets Processed
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="error.main">
                    {(systemStatus.stats?.packets_dropped || 0).toLocaleString()}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Packets Dropped
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="info.main">
                    {((systemStatus.stats?.bytes_processed || 0) / 1024 / 1024).toFixed(2)} MB
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Bytes Processed
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box textAlign="center">
                  <Typography variant="h4" color="warning.main">
                    {(systemStatus.stats?.cpu_usage || 0).toFixed(1)}%
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    CPU Usage
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default EBPFControl; 