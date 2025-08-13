import React, { useState, useEffect } from 'react';
import {
  Switch,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Alert,
  Box,
  Typography,
  Chip,
  CircularProgress,
  Card,
  CardContent,
  Grid,
} from '@mui/material';
import {
  Warning,
  CheckCircle,
  Error,
  Security,
} from '@mui/icons-material';

interface LiveToggleProps {
  onModeChange?: (mode: 'simulation' | 'live') => void;
}

interface LiveStatus {
  mode: 'simulation' | 'live' | 'emergency';
  last_commit: number;
  rule_count: number;
  drop_count: number;
  allow_count: number;
  emergency_mode: boolean;
  watchdog_running: boolean;
}

const LiveToggle: React.FC<LiveToggleProps> = ({ onModeChange }) => {
  const [live, setLive] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [confirmationText, setConfirmationText] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<LiveStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Fetch current status
  const fetchStatus = async () => {
    try {
      const response = await fetch('/api/live/status');
      if (response.ok) {
        const data = await response.json();
        setStatus(data);
        setLive(data.mode === 'live');
      }
    } catch (err) {
      console.error('Failed to fetch live status:', err);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000); // Update every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const handleChange = async (next: boolean) => {
    if (next) {
      setConfirm(true);
      return;
    }
    
    await switchMode('simulation');
  };

  const switchMode = async (mode: 'simulation' | 'live') => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch('/api/live/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setLive(mode === 'live');
          onModeChange?.(mode);
          await fetchStatus();
        } else {
          setError(data.message || 'Failed to switch mode');
        }
      } else {
        setError('Network error');
      }
    } catch (err) {
      setError('Failed to switch mode');
    } finally {
      setLoading(false);
    }
  };

  const handleConfirm = async () => {
    if (confirmationText !== 'LIVE') {
      setError('Please type "LIVE" to confirm');
      return;
    }
    
    await switchMode('live');
    setConfirm(false);
    setConfirmationText('');
  };

  const getModeColor = () => {
    if (!status) return 'default';
    switch (status.mode) {
      case 'live': return 'success';
      case 'emergency': return 'error';
      default: return 'default';
    }
  };

  const getModeIcon = () => {
    if (!status) return <Security />;
    switch (status.mode) {
      case 'live': return <CheckCircle />;
      case 'emergency': return <Error />;
      default: return <Security />;
    }
  };

  const formatTimestamp = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const calculateDropRate = () => {
    if (!status) return 0;
    const total = status.drop_count + status.allow_count;
    return total > 0 ? (status.drop_count / total) * 100 : 0;
  };

  return (
    <Box>
      {/* Live Mode Status Card */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item>
              <Box display="flex" alignItems="center" gap={1}>
                {getModeIcon()}
                <Typography variant="h6">
                  LIVE Mode: {status?.mode?.toUpperCase() || 'UNKNOWN'}
                </Typography>
                <Chip 
                  label={status?.mode?.toUpperCase() || 'UNKNOWN'} 
                  color={getModeColor() as any}
                  size="small"
                />
              </Box>
            </Grid>
            
            <Grid item xs>
              <Box display="flex" gap={2}>
                <Typography variant="body2">
                  Rules: {status?.rule_count || 0}
                </Typography>
                <Typography variant="body2">
                  Drops: {status?.drop_count || 0}
                </Typography>
                <Typography variant="body2">
                  Allows: {status?.allow_count || 0}
                </Typography>
                <Typography variant="body2">
                  Drop Rate: {calculateDropRate().toFixed(1)}%
                </Typography>
              </Box>
            </Grid>
            
            <Grid item>
              <Switch
                checked={live}
                onChange={(e) => handleChange(e.target.checked)}
                disabled={loading}
                color="success"
              />
            </Grid>
          </Grid>
          
          {status?.last_commit && (
            <Typography variant="caption" color="text.secondary">
              Last commit: {formatTimestamp(status.last_commit)}
            </Typography>
          )}
          
          {status?.emergency_mode && (
            <Alert severity="error" sx={{ mt: 1 }}>
              Emergency mode active - system has automatically rolled back to simulation
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Confirmation Dialog */}
      <Dialog open={confirm} onClose={() => setConfirm(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Box display="flex" alignItems="center" gap={1}>
            <Warning color="warning" />
            Enable LIVE Mode?
          </Box>
        </DialogTitle>
        
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="body2" sx={{ mb: 1 }}>
              <strong>WARNING:</strong> Enabling LIVE mode will:
            </Typography>
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              <li>Start dropping packets instantly based on firewall rules</li>
              <li>Activate rate limiting and per-CPU monitoring</li>
              <li>Enable emergency rollback on system stress</li>
              <li>Require manual confirmation for critical operations</li>
            </ul>
          </Alert>
          
          <Typography variant="body2" sx={{ mb: 2 }}>
            Type <strong>"LIVE"</strong> to confirm you understand the risks:
          </Typography>
          
          <TextField
            fullWidth
            value={confirmationText}
            onChange={(e) => setConfirmationText(e.target.value)}
            placeholder="Type 'LIVE' to confirm"
            error={!!error}
            helperText={error}
          />
        </DialogContent>
        
        <DialogActions>
          <Button onClick={() => setConfirm(false)} disabled={loading}>
            Cancel
          </Button>
          <Button 
            onClick={handleConfirm}
            variant="contained"
            color="warning"
            disabled={confirmationText !== 'LIVE' || loading}
            startIcon={loading ? <CircularProgress size={16} /> : null}
          >
            Enable LIVE Mode
          </Button>
        </DialogActions>
      </Dialog>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
    </Box>
  );
};

export default LiveToggle; 