// SPDX-License-Identifier: Apache-2.0
// Firewall Configuration Page

import React, { useState, useEffect } from 'react';
import {
  Typography,
  Paper,
  Box,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Button,
  TextField,
  Switch,
  FormControlLabel,
  Alert,
  Divider,
  Grid,
  Card,
  CardContent,
  Chip,
} from '@mui/material';
import { Save, Refresh, NetworkCheck, Security } from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import toast from 'react-hot-toast';

import { firewallAPI } from '../services/api';

interface InterfaceInfo {
  name: string;
  is_up: boolean;
  rx_packets: number;
  tx_packets: number;
  rx_bytes: number;
  tx_bytes: number;
}

interface FirewallConfig {
  interface: string;
  xdp_program: string;
  queue_id: number;
  verbose: boolean;
  auto_start: boolean;
}

const Configuration: React.FC = () => {
  const queryClient = useQueryClient();
  const [config, setConfig] = useState<FirewallConfig>({
    interface: 'auto',  // Auto-detect by default
    xdp_program: 'ebpf/xdp_filter.o',
    queue_id: 0,
    verbose: true,
    auto_start: false,
  });

  // Queries
  const { data: interfaces } = useQuery<InterfaceInfo[]>(
    'network-interfaces',
    firewallAPI.getInterfaces,
    { refetchInterval: 10000 }
  );

  const { data: detailedInterfaces } = useQuery(
    'detailed-interfaces',
    firewallAPI.getInterfacesDetailed,
    { refetchInterval: 10000 }
  );

  const { data: activeInterface } = useQuery(
    'active-interface',
    firewallAPI.getActiveInterface
  );

  const { data: status } = useQuery(
    'firewall-status',
    firewallAPI.getStatus
  );

  // Update config when status loads
  useEffect(() => {
    if (status?.config) {
      setConfig(status.config);
    }
  }, [status]);

  // Start firewall mutation
  const startMutation = useMutation(firewallAPI.start, {
    onSuccess: () => {
      toast.success('Firewall configuration applied successfully!');
      queryClient.invalidateQueries('firewall-status');
    },
    onError: (error: any) => {
      toast.error(`Failed to apply configuration: ${error.message}`);
    },
  });

  const handleApplyConfig = () => {
    startMutation.mutate(config);
  };

  const handleAutoDetect = () => {
    const recommended = detailedInterfaces?.recommended || activeInterface?.active_interface;
    if (recommended) {
      setConfig(prev => ({
        ...prev,
        interface: recommended
      }));
      toast.success(`Interface set to: ${recommended} (auto-detected)`);
    }
  };

  const formatBytes = (bytes: number) => {
    const sizes = ['B', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Security color="primary" />
        Firewall Configuration
      </Typography>

      {/* Current Status */}
      <Alert 
        severity={status?.is_running ? 'success' : 'info'} 
        sx={{ mb: 3 }}
      >
        Firewall is currently {status?.is_running ? 'RUNNING' : 'STOPPED'}
        {status?.is_running && ` on interface ${status.config.interface}`}
      </Alert>

      <Grid container spacing={3}>
        {/* Main Configuration */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              🛡️ eBPF Firewall Settings
            </Typography>

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {/* Interface Selection */}
              <Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="subtitle1" fontWeight={600}>
                    Network Interface
                  </Typography>
                  <Button
                    size="small"
                    startIcon={<Refresh />}
                    onClick={handleAutoDetect}
                    disabled={!activeInterface}
                  >
                    Auto-detect
                  </Button>
                </Box>

                <FormControl fullWidth>
                  <InputLabel>Network Interface</InputLabel>
                  <Select
                    value={config.interface}
                    label="Network Interface"
                    onChange={(e) => setConfig(prev => ({ ...prev, interface: e.target.value }))}
                  >
                    {/* Add auto-detect option */}
                    <MenuItem value="auto">
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                        <span>🔍 Auto-detect (Recommended)</span>
                        <Chip size="small" label="AUTO" color="secondary" />
                      </Box>
                    </MenuItem>
                    
                    {detailedInterfaces?.interfaces?.map((iface) => (
                      <MenuItem key={iface.name} value={iface.name}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <span>{iface.name}</span>
                            {iface.type === 'wireless' && '📶'}
                            {iface.type === 'ethernet' && '🔌'}
                            {iface.type === 'loopback' && '🔄'}
                            {iface.type === 'virtual' && '🖥️'}
                          </Box>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Chip 
                              size="small" 
                              label={iface.is_up ? 'UP' : 'DOWN'} 
                              color={iface.is_up ? 'success' : 'error'}
                            />
                            {iface.name === detailedInterfaces.recommended && (
                              <Chip size="small" label="RECOMMENDED" color="primary" />
                            )}
                            {iface.is_physical && (
                              <Chip size="small" label="PHYSICAL" color="info" />
                            )}
                          </Box>
                        </Box>
                      </MenuItem>
                    )) || interfaces?.map((iface) => (
                      <MenuItem key={iface.name} value={iface.name}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                          <span>{iface.name}</span>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Chip 
                              size="small" 
                              label={iface.is_up ? 'UP' : 'DOWN'} 
                              color={iface.is_up ? 'success' : 'error'}
                            />
                          </Box>
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>

              <Divider />

              {/* XDP Program */}
              <TextField
                label="XDP Program Path"
                value={config.xdp_program}
                onChange={(e) => setConfig(prev => ({ ...prev, xdp_program: e.target.value }))}
                fullWidth
                helperText="Path to the compiled eBPF/XDP program"
              />

              {/* Queue ID */}
              <TextField
                label="Queue ID"
                type="number"
                value={config.queue_id}
                onChange={(e) => setConfig(prev => ({ ...prev, queue_id: parseInt(e.target.value) }))}
                fullWidth
                helperText="AF_XDP queue identifier"
              />

              {/* Options */}
              <Box>
                <Typography variant="subtitle2" gutterBottom>Options</Typography>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.verbose}
                      onChange={(e) => setConfig(prev => ({ ...prev, verbose: e.target.checked }))}
                    />
                  }
                  label="Verbose logging"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.auto_start}
                      onChange={(e) => setConfig(prev => ({ ...prev, auto_start: e.target.checked }))}
                    />
                  }
                  label="Auto-start on boot"
                />
              </Box>

              {/* Apply Button */}
              <Button
                variant="contained"
                size="large"
                startIcon={<Save />}
                onClick={handleApplyConfig}
                disabled={startMutation.isLoading}
                sx={{ mt: 2 }}
              >
                {startMutation.isLoading ? 'Applying...' : 'Apply Configuration'}
              </Button>
            </Box>
          </Paper>
        </Grid>

        {/* Interface Information */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <NetworkCheck color="primary" />
              Network Interfaces
            </Typography>

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {detailedInterfaces?.interfaces?.map((iface) => (
                <Card 
                  key={iface.name} 
                  variant="outlined" 
                  sx={{ 
                    bgcolor: iface.name === config.interface ? 'action.selected' : 'transparent',
                    border: iface.name === config.interface ? 2 : 1,
                    borderColor: iface.name === config.interface ? 'primary.main' : 'divider',
                    cursor: 'pointer',
                    '&:hover': {
                      bgcolor: 'action.hover'
                    }
                  }}
                  onClick={() => setConfig(prev => ({ ...prev, interface: iface.name }))}
                >
                  <CardContent sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="subtitle2" fontWeight={600}>
                          {iface.name}
                        </Typography>
                        {iface.type === 'wireless' && '📶'}
                        {iface.type === 'ethernet' && '🔌'}
                        {iface.type === 'loopback' && '🔄'}
                        {iface.type === 'virtual' && '🖥️'}
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        <Chip 
                          size="small" 
                          label={iface.is_up ? 'UP' : 'DOWN'} 
                          color={iface.is_up ? 'success' : 'error'}
                        />
                        {iface.name === detailedInterfaces.recommended && (
                          <Chip size="small" label="RECOMMENDED" color="primary" />
                        )}
                        {iface.is_physical && (
                          <Chip size="small" label="PHYSICAL" color="info" />
                        )}
                      </Box>
                    </Box>
                    
                    {iface.ip_addresses.length > 0 && (
                      <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                        IP: {iface.ip_addresses.join(', ')}
                      </Typography>
                    )}
                    
                    <Typography variant="caption" color="text.secondary" display="block">
                      RX: {formatBytes(iface.rx_bytes)} ({iface.rx_packets.toLocaleString()} packets)
                    </Typography>
                    <Typography variant="caption" color="text.secondary" display="block">
                      TX: {formatBytes(iface.tx_bytes)} ({iface.tx_packets.toLocaleString()} packets)
                    </Typography>
                    
                    {iface.mtu && (
                      <Typography variant="caption" color="text.secondary" display="block">
                        MTU: {iface.mtu}
                      </Typography>
                    )}
                  </CardContent>
                </Card>
              )) || interfaces?.map((iface) => (
                <Card 
                  key={iface.name} 
                  variant="outlined" 
                  sx={{ 
                    bgcolor: iface.name === config.interface ? 'action.selected' : 'transparent',
                    border: iface.name === config.interface ? 2 : 1,
                    borderColor: iface.name === config.interface ? 'primary.main' : 'divider'
                  }}
                >
                  <CardContent sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                      <Typography variant="subtitle2" fontWeight={600}>
                        {iface.name}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Chip 
                          size="small" 
                          label={iface.is_up ? 'UP' : 'DOWN'} 
                          color={iface.is_up ? 'success' : 'error'}
                        />
                      </Box>
                    </Box>
                    
                    <Typography variant="caption" color="text.secondary" display="block">
                      RX: {formatBytes(iface.rx_bytes)} ({iface.rx_packets.toLocaleString()} packets)
                    </Typography>
                    <Typography variant="caption" color="text.secondary" display="block">
                      TX: {formatBytes(iface.tx_bytes)} ({iface.tx_packets.toLocaleString()} packets)
                    </Typography>
                  </CardContent>
                </Card>
              ))}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Configuration; 