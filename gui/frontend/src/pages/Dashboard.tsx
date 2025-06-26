// SPDX-License-Identifier: Apache-2.0
// VPP eBPF Firewall Dashboard - Elite Senior Edition

import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Chip,
  Button,
  Container,
  CardHeader,
  Alert,
  LinearProgress,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Switch,
  FormControlLabel,
  Tabs,
  Tab,
  TextField,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tooltip,
} from '@mui/material';
import {
  Security,
  NetworkCheck,
  CheckCircle,
  Block,
  WifiTwoTone,
  Computer,
  Speed,
  Memory,
  Storage,
  ExpandMore,
  Add,
  Delete,
  Edit,
  Save,
  Settings,
  Shield,
  Visibility,
  VisibilityOff,
  FlashOn,
  School,
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { useWebSocket } from '../contexts/WebSocketContext';
import { firewallAPI } from '../services/api';

// Elite Firewall Configuration Types
interface FirewallMode {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  color: 'success' | 'warning' | 'error' | 'info' | 'primary';
  settings: {
    defaultAction: 'allow' | 'deny';
    logging: boolean;
    performance: 'high' | 'balanced' | 'strict';
  };
}

interface FirewallRule {
  id: string;
  name: string;
  enabled: boolean;
  protocol: 'tcp' | 'udp' | 'icmp' | 'any';
  sourceIp: string;
  destinationIp: string;
  sourcePort: string;
  destinationPort: string;
  action: 'allow' | 'deny' | 'log';
  priority: number;
}

interface TrafficFilter {
  id: string;
  name: string;
  type: 'ip' | 'port' | 'protocol' | 'geo' | 'application';
  value: string;
  action: 'block' | 'allow' | 'monitor';
  enabled: boolean;
}

// Elite Firewall Modes Configuration
const FIREWALL_MODES: FirewallMode[] = [
  {
    id: 'strict',
    name: 'Strict Mode',
    description: 'Block everything except explicitly allowed traffic',
    icon: <Shield />,
    color: 'error',
    settings: { defaultAction: 'deny', logging: true, performance: 'strict' }
  },
  {
    id: 'balanced',
    name: 'Balanced Mode',
    description: 'Smart filtering with performance optimization',
    icon: <Security />,
    color: 'primary',
    settings: { defaultAction: 'allow', logging: true, performance: 'balanced' }
  },
  {
    id: 'permissive',
    name: 'Permissive Mode',
    description: 'Allow everything except explicitly blocked traffic',
    icon: <CheckCircle />,
    color: 'success',
    settings: { defaultAction: 'allow', logging: false, performance: 'high' }
  },
  {
    id: 'learning',
    name: 'Learning Mode',
    description: 'Monitor traffic and suggest optimal rules',
    icon: <School />,
    color: 'info',
    settings: { defaultAction: 'allow', logging: true, performance: 'balanced' }
  },
  {
    id: 'performance',
    name: 'Performance Mode',
    description: 'Minimal processing for maximum throughput',
    icon: <FlashOn />,
    color: 'warning',
    settings: { defaultAction: 'allow', logging: false, performance: 'high' }
  },
  {
    id: 'monitoring',
    name: 'Monitor Only',
    description: 'Log all traffic without blocking',
    icon: <Visibility />,
    color: 'info',
    settings: { defaultAction: 'allow', logging: true, performance: 'balanced' }
  }
];

// Elite Configuration Panel Component
const FirewallConfigurationPanel: React.FC = () => {
  const { data, isConnected } = useWebSocket();
  const [selectedMode, setSelectedMode] = useState<string>('balanced');
  const [customRules, setCustomRules] = useState<FirewallRule[]>([]);
  const [trafficFilters, setTrafficFilters] = useState<TrafficFilter[]>([]);
  const [activeTab, setActiveTab] = useState(0);
  const [showRuleDialog, setShowRuleDialog] = useState(false);
  const [editingRule, setEditingRule] = useState<FirewallRule | null>(null);

  // Default rules for demonstration
  useEffect(() => {
    setCustomRules([
      {
        id: '1',
        name: 'Block SSH Brute Force',
        enabled: true,
        protocol: 'tcp',
        sourceIp: 'any',
        destinationIp: 'any',
        sourcePort: 'any',
        destinationPort: '22',
        action: 'deny',
        priority: 100
      },
      {
        id: '2', 
        name: 'Allow HTTP/HTTPS',
        enabled: true,
        protocol: 'tcp',
        sourceIp: 'any',
        destinationIp: 'any',
        sourcePort: 'any',
        destinationPort: '80,443',
        action: 'allow',
        priority: 50
      }
    ]);

    setTrafficFilters([
      {
        id: '1',
        name: 'Block Malicious IPs',
        type: 'ip',
        value: '192.168.100.0/24',
        action: 'block',
        enabled: true
      },
      {
        id: '2',
        name: 'Monitor DNS Traffic',
        type: 'port',
        value: '53',
        action: 'monitor',
        enabled: true
      }
    ]);
  }, []);

  const currentMode = FIREWALL_MODES.find(mode => mode.id === selectedMode);

  const handleModeChange = async (modeId: string) => {
    setSelectedMode(modeId);
    const mode = FIREWALL_MODES.find(m => m.id === modeId);
    if (mode && isConnected) {
      try {
        // Здесь будет API вызов для изменения режима
        console.log(`🎯 Switching to ${mode.name} mode`, mode.settings);
      } catch (error) {
        console.error('Failed to change firewall mode:', error);
      }
    }
  };

  const handleAddRule = () => {
    setEditingRule({
      id: Date.now().toString(),
      name: '',
      enabled: true,
      protocol: 'tcp',
      sourceIp: 'any',
      destinationIp: 'any',
      sourcePort: 'any',
      destinationPort: '',
      action: 'allow',
      priority: 50
    });
    setShowRuleDialog(true);
  };

  const handleSaveRule = () => {
    if (editingRule) {
      if (editingRule.id && customRules.find(r => r.id === editingRule.id)) {
        setCustomRules(prev => prev.map(r => r.id === editingRule.id ? editingRule : r));
      } else {
        setCustomRules(prev => [...prev, { ...editingRule, id: Date.now().toString() }]);
      }
      setShowRuleDialog(false);
      setEditingRule(null);
    }
  };

  const handleDeleteRule = (ruleId: string) => {
    setCustomRules(prev => prev.filter(r => r.id !== ruleId));
  };

  const toggleRuleEnabled = (ruleId: string) => {
    setCustomRules(prev => prev.map(r => 
      r.id === ruleId ? { ...r, enabled: !r.enabled } : r
    ));
  };

  return (
    <Card>
      <CardHeader 
        title="🎯 Elite Firewall Configuration" 
        subheader="Advanced customization and rule management"
      />
      <CardContent>
        <Tabs value={activeTab} onChange={(_, newValue) => setActiveTab(newValue)}>
          <Tab label="Modes" />
          <Tab label="Rules" />
          <Tab label="Filters" />
          <Tab label="Presets" />
        </Tabs>

        {/* Mode Selection Tab */}
        {activeTab === 0 && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>
              🛡️ Firewall Operating Modes
            </Typography>
            <Grid container spacing={2}>
              {FIREWALL_MODES.map((mode) => (
                <Grid item xs={12} sm={6} md={4} key={mode.id}>
                  <Card 
                    variant={selectedMode === mode.id ? "outlined" : "elevation"}
                    sx={{ 
                      cursor: 'pointer',
                      border: selectedMode === mode.id ? 2 : 0,
                      borderColor: selectedMode === mode.id ? `${mode.color}.main` : 'transparent'
                    }}
                    onClick={() => handleModeChange(mode.id)}
                  >
                    <CardContent>
                      <Box display="flex" alignItems="center" gap={1} mb={1}>
                        <Box sx={{ color: `${mode.color}.main` }}>
                          {mode.icon}
                        </Box>
                        <Typography variant="h6">{mode.name}</Typography>
                        {selectedMode === mode.id && (
                          <Chip label="Active" color={mode.color} size="small" />
                        )}
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        {mode.description}
                      </Typography>
                      <Box mt={2}>
                        <Typography variant="caption" display="block">
                          Default: {mode.settings.defaultAction.toUpperCase()}
                        </Typography>
                        <Typography variant="caption" display="block">
                          Performance: {mode.settings.performance.toUpperCase()}
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            {currentMode && (
              <Alert severity="info" sx={{ mt: 3 }}>
                <strong>{currentMode.name}</strong>: {currentMode.description}
              </Alert>
            )}
          </Box>
        )}

        {/* Custom Rules Tab */}
        {activeTab === 1 && (
          <Box sx={{ mt: 3 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">⚡ Custom Firewall Rules</Typography>
              <Button
                variant="contained"
                startIcon={<Add />}
                onClick={handleAddRule}
                disabled={!isConnected}
              >
                Add Rule
              </Button>
            </Box>

            <List>
              {customRules.map((rule) => (
                <ListItem key={rule.id} divider>
                  <Box display="flex" alignItems="center" gap={1} mr={2}>
                    <Switch
                      checked={rule.enabled}
                      onChange={() => toggleRuleEnabled(rule.id)}
                      size="small"
                    />
                    <Chip 
                      label={rule.action.toUpperCase()}
                      color={rule.action === 'allow' ? 'success' : rule.action === 'deny' ? 'error' : 'info'}
                      size="small"
                    />
                  </Box>
                  <ListItemText
                    primary={rule.name}
                    secondary={`${rule.protocol.toUpperCase()} ${rule.sourceIp}:${rule.sourcePort} → ${rule.destinationIp}:${rule.destinationPort}`}
                  />
                  <ListItemSecondaryAction>
                    <Tooltip title="Edit Rule">
                      <IconButton
                        edge="end"
                        onClick={() => {
                          setEditingRule(rule);
                          setShowRuleDialog(true);
                        }}
                      >
                        <Edit />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete Rule">
                      <IconButton
                        edge="end"
                        onClick={() => handleDeleteRule(rule.id)}
                        color="error"
                      >
                        <Delete />
                      </IconButton>
                    </Tooltip>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>

            {customRules.length === 0 && (
              <Alert severity="info">
                No custom rules configured. Click "Add Rule" to create your first rule.
              </Alert>
            )}
          </Box>
        )}

        {/* Traffic Filters Tab */}
        {activeTab === 2 && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>
              🌐 Traffic Filters
            </Typography>
            <Grid container spacing={2}>
              {trafficFilters.map((filter) => (
                <Grid item xs={12} sm={6} key={filter.id}>
                  <Card variant="outlined">
                    <CardContent>
                      <Box display="flex" justifyContent="space-between" alignItems="center">
                        <Typography variant="h6">{filter.name}</Typography>
                        <Switch
                          checked={filter.enabled}
                          onChange={() => {
                            setTrafficFilters(prev => prev.map(f =>
                              f.id === filter.id ? { ...f, enabled: !f.enabled } : f
                            ));
                          }}
                        />
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        Type: {filter.type.toUpperCase()}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Value: {filter.value}
                      </Typography>
                      <Chip 
                        label={filter.action.toUpperCase()}
                        color={filter.action === 'block' ? 'error' : filter.action === 'allow' ? 'success' : 'info'}
                        size="small"
                        sx={{ mt: 1 }}
                      />
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Box>
        )}

        {/* Presets Tab */}
        {activeTab === 3 && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="h6" gutterBottom>
              🎮 Quick Presets
            </Typography>
            <Grid container spacing={2}>
              {[
                { name: 'Gaming Setup', desc: 'Optimized for gaming with low latency', icon: '🎮' },
                { name: 'Server Mode', desc: 'Strict security for server environments', icon: '🖥️' },
                { name: 'Development', desc: 'Relaxed rules for development work', icon: '💻' },
                { name: 'High Security', desc: 'Maximum protection configuration', icon: '🔒' }
              ].map((preset, index) => (
                <Grid item xs={12} sm={6} key={index}>
                  <Card 
                    variant="outlined" 
                    sx={{ cursor: 'pointer' }}
                    onClick={() => console.log(`Applying ${preset.name} preset`)}
                  >
                    <CardContent>
                      <Typography variant="h6">
                        {preset.icon} {preset.name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {preset.desc}
                      </Typography>
                      <Button 
                        variant="outlined" 
                        size="small" 
                        sx={{ mt: 2 }}
                        disabled={!isConnected}
                      >
                        Apply Preset
                      </Button>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Box>
        )}
      </CardContent>

      {/* Rule Edit Dialog */}
      <Dialog open={showRuleDialog} onClose={() => setShowRuleDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {editingRule?.id && customRules.find(r => r.id === editingRule.id) ? 'Edit Rule' : 'Add New Rule'}
        </DialogTitle>
        <DialogContent>
          {editingRule && (
            <Grid container spacing={2} sx={{ mt: 1 }}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Rule Name"
                  value={editingRule.name}
                  onChange={(e) => setEditingRule({ ...editingRule, name: e.target.value })}
                />
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Protocol</InputLabel>
                  <Select
                    value={editingRule.protocol}
                    onChange={(e) => setEditingRule({ ...editingRule, protocol: e.target.value as any })}
                  >
                    <MenuItem value="tcp">TCP</MenuItem>
                    <MenuItem value="udp">UDP</MenuItem>
                    <MenuItem value="icmp">ICMP</MenuItem>
                    <MenuItem value="any">Any</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Action</InputLabel>
                  <Select
                    value={editingRule.action}
                    onChange={(e) => setEditingRule({ ...editingRule, action: e.target.value as any })}
                  >
                    <MenuItem value="allow">Allow</MenuItem>
                    <MenuItem value="deny">Deny</MenuItem>
                    <MenuItem value="log">Log Only</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Source IP"
                  value={editingRule.sourceIp}
                  onChange={(e) => setEditingRule({ ...editingRule, sourceIp: e.target.value })}
                  placeholder="any, 192.168.1.0/24, 10.0.0.1"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Source Port"
                  value={editingRule.sourcePort}
                  onChange={(e) => setEditingRule({ ...editingRule, sourcePort: e.target.value })}
                  placeholder="any, 80, 1000-2000"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Destination IP"
                  value={editingRule.destinationIp}
                  onChange={(e) => setEditingRule({ ...editingRule, destinationIp: e.target.value })}
                  placeholder="any, 192.168.1.0/24, 10.0.0.1"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  label="Destination Port"
                  value={editingRule.destinationPort}
                  onChange={(e) => setEditingRule({ ...editingRule, destinationPort: e.target.value })}
                  placeholder="any, 80, 443, 1000-2000"
                />
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowRuleDialog(false)}>Cancel</Button>
          <Button onClick={handleSaveRule} variant="contained">Save Rule</Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
};

// Elite Stats Card Component
const StatsCard: React.FC<{
  title: string;
  value?: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  color?: 'success' | 'error' | 'warning' | 'info' | 'primary';
  children?: React.ReactNode;
}> = ({ title, value, subtitle, icon, color = 'primary', children }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Box display="flex" alignItems="center" gap={2}>
        <Box sx={{ color: `${color}.main` }}>
          {icon}
        </Box>
        <Box flex={1}>
          <Typography variant="body2" color="text.secondary">
            {title}
          </Typography>
          {value !== undefined && (
            <Typography variant="h4" color={`${color}.main`} sx={{ fontWeight: 'bold' }}>
              {typeof value === 'number' ? value.toLocaleString() : value}
            </Typography>
          )}
          {subtitle && (
            <Typography variant="body2" color="text.secondary">
              {subtitle}
            </Typography>
          )}
          {children}
        </Box>
      </Box>
    </CardContent>
  </Card>
);

// Firewall Status Card - Elite Edition
const FirewallStatusCard: React.FC = () => {
  const { data, connectionState, isConnected, forceReconnect } = useWebSocket();

  const isFirewallRunning = data?.data?.is_running || false;
  const firewallUptime = data?.data?.uptime || "0:00:00";
  
  const getFirewallStatusColor = (): 'success' | 'error' | 'default' => {
    if (!isConnected) return 'default';
    return isFirewallRunning ? 'success' : 'error';
  };

  const getFirewallStatusText = () => {
    if (!isConnected) return 'NO CONNECTION';
    return isFirewallRunning ? 'ONLINE' : 'OFFLINE';
  };

  const getWebSocketStatusColor = (): 'success' | 'warning' | 'error' | 'default' => {
    switch (connectionState) {
      case 'connected': return 'success';
      case 'connecting':
      case 'reconnecting': return 'warning';
      case 'error': return 'error';
      default: return 'default';
    }
  };

  return (
    <Card>
      <CardHeader title="🔥 System Status" />
      <CardContent>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Firewall Engine
            </Typography>
            <Chip 
              label={getFirewallStatusText()}
              color={getFirewallStatusColor()}
              variant="filled"
              sx={{ fontWeight: 'bold', mb: 1 }}
            />
            {isFirewallRunning && (
              <Typography variant="body2" color="text.secondary">
                ⏱ Uptime: {firewallUptime}
              </Typography>
            )}
          </Grid>
          
          <Grid item xs={12} sm={6}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              WebSocket Connection
            </Typography>
            <Chip 
              label={connectionState.toUpperCase()}
              color={getWebSocketStatusColor()}
              variant="filled"
              sx={{ fontWeight: 'bold', mb: 1 }}
            />
            {!isConnected && (
              <Box>
                <Button
                  variant="outlined"
                  onClick={forceReconnect}
                  size="small"
                  sx={{ mt: 1 }}
                >
                  🔄 Reconnect
                </Button>
              </Box>
            )}
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
};

// System Info Card - Elite Edition
const SystemInfoCard: React.FC = () => {
  const { data } = useWebSocket();
  
  const systemInfo = data?.data?.system_info;
  const hostname = systemInfo?.hostname || 'N/A';
  const kernelVersion = systemInfo?.kernel_version || 'N/A';
  const cpuCores = systemInfo?.cpu_cores || 0;
  const totalMemoryGB = systemInfo?.total_memory 
    ? (systemInfo.total_memory / 1024 / 1024 / 1024).toFixed(1) 
    : '0';

  return (
    <Card>
      <CardHeader title="💻 System Information" />
      <CardContent>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6} md={3}>
            <Box textAlign="center">
              <Computer color="primary" sx={{ fontSize: 32, mb: 1 }} />
              <Typography variant="body2" color="text.secondary">Hostname</Typography>
              <Typography variant="h6" sx={{ fontFamily: 'monospace', fontWeight: 'bold' }}>
                {hostname}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Box textAlign="center">
              <Storage color="primary" sx={{ fontSize: 32, mb: 1 }} />
              <Typography variant="body2" color="text.secondary">OS</Typography>
              <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                Linux
              </Typography>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                {kernelVersion}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Box textAlign="center">
              <Speed color="primary" sx={{ fontSize: 32, mb: 1 }} />
              <Typography variant="body2" color="text.secondary">CPU Cores</Typography>
              <Typography variant="h6" sx={{ fontFamily: 'monospace', fontWeight: 'bold' }}>
                {cpuCores}
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Box textAlign="center">
              <Memory color="primary" sx={{ fontSize: 32, mb: 1 }} />
              <Typography variant="body2" color="text.secondary">Memory</Typography>
              <Typography variant="h6" sx={{ fontFamily: 'monospace', fontWeight: 'bold' }}>
                {totalMemoryGB} GB
              </Typography>
            </Box>
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
};

// Network Interface Card - Elite Edition
const NetworkInterfaceCard: React.FC = () => {
  const { data } = useWebSocket();
  
  return (
    <Card>
      <CardHeader title="🌐 Network Interfaces" />
      <CardContent>
        {data?.data?.interfaces && data.data.interfaces.length > 0 ? (
          data.data.interfaces.map((iface: any, index: number) => (
            <Box key={index} mb={2} p={2} border={1} borderColor="divider" borderRadius={1}>
              <Box display="flex" alignItems="center" gap={1} mb={1}>
                <WifiTwoTone color={iface.status === 'up' ? 'primary' : 'disabled'} />
                <Typography variant="h6">{iface.name}</Typography>
                <Chip 
                  label={iface.status.toUpperCase()} 
                  size="small"
                  color={iface.status === 'up' ? 'success' : 'default'}
                />
              </Box>
              <Typography variant="body2" color="text.secondary">
                IP: {iface.ip_address || 'N/A'} | MAC: {iface.mac_address} | MTU: {iface.mtu}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                RX: {iface.rx_packets.toLocaleString()} packets ({(iface.rx_bytes / 1024 / 1024).toFixed(1)} MB)
              </Typography>
              <Typography variant="body2" color="text.secondary">
                TX: {iface.tx_packets.toLocaleString()} packets ({(iface.tx_bytes / 1024 / 1024).toFixed(1)} MB)
              </Typography>
            </Box>
          ))
        ) : (
          <Alert severity="info">
            No interface data available
          </Alert>
        )}
      </CardContent>
    </Card>
  );
};

// Quick Actions Panel - Elite Edition
const QuickActionsPanel: React.FC = () => {
  const { data, isConnected } = useWebSocket();
  const [loading, setLoading] = useState<string | null>(null);
  const [activeInterface, setActiveInterface] = useState<string>('auto');

  const isFirewallRunning = data?.data?.is_running || false;

  const handleStartFirewall = async () => {
    if (!isConnected) return;
    
    setLoading('start');
    try {
      await firewallAPI.start({
        interface: activeInterface,
        xdp_program: 'ebpf/xdp_filter.o',
        queue_id: 0,
        verbose: true,
        auto_start: false
      });
      console.log('✅ Firewall started successfully');
    } catch (error) {
      console.error('❌ Failed to start firewall:', error);
    } finally {
      setLoading(null);
    }
  };

  const handleStopFirewall = async () => {
    if (!isConnected) return;
    
    setLoading('stop');
    try {
      await firewallAPI.stop();
      console.log('✅ Firewall stopped successfully');
    } catch (error) {
      console.error('❌ Failed to stop firewall:', error);
    } finally {
      setLoading(null);
    }
  };

  const handleRestartFirewall = async () => {
    if (!isConnected) return;
    
    setLoading('restart');
    try {
      await firewallAPI.restart();
      console.log('✅ Firewall restarted successfully');
    } catch (error) {
      console.error('❌ Failed to restart firewall:', error);
    } finally {
      setLoading(null);
    }
  };

  return (
    <Grid container spacing={2}>
      <Grid item xs={12} sm={6}>
        <Button 
          variant="contained" 
          color="success"
          fullWidth
          disabled={!isConnected || isFirewallRunning || loading === 'start'}
          onClick={handleStartFirewall}
          startIcon={loading === 'start' ? <Speed /> : <CheckCircle />}
        >
          {loading === 'start' ? 'Starting...' : 'Start Firewall'}
        </Button>
      </Grid>
      <Grid item xs={12} sm={6}>
        <Button 
          variant="contained" 
          color="error"
          fullWidth
          disabled={!isConnected || !isFirewallRunning || loading === 'stop'}
          onClick={handleStopFirewall}
          startIcon={loading === 'stop' ? <Speed /> : <Block />}
        >
          {loading === 'stop' ? 'Stopping...' : 'Stop Firewall'}
        </Button>
      </Grid>
      <Grid item xs={12} sm={6}>
        <Button 
          variant="outlined" 
          color="warning"
          fullWidth
          disabled={!isConnected || !isFirewallRunning || loading === 'restart'}
          onClick={handleRestartFirewall}
          startIcon={loading === 'restart' ? <Speed /> : <Security />}
        >
          {loading === 'restart' ? 'Restarting...' : 'Restart Firewall'}
        </Button>
      </Grid>
      <Grid item xs={12} sm={6}>
        <Button 
          variant="outlined" 
          fullWidth
          disabled={!isConnected}
          onClick={() => window.open('/api/docs', '_blank')}
          startIcon={<Computer />}
        >
          API Docs
        </Button>
      </Grid>
    </Grid>
  );
};

// Elite Dashboard Component
const Dashboard: React.FC = () => {
  const { data, isConnected } = useWebSocket();
  const [chartData, setChartData] = useState<any[]>([]);

  // Elite data extraction with proper typing
  const firewallStats = data?.data?.firewall_stats as any || {};
  const packetsDropped = (firewallStats.packets_dropped as number) || 0;
  const packetsPassed = (firewallStats.packets_passed as number) || 0;
  const packetsTotal = packetsDropped + packetsPassed;
  const ppsCurrently = (firewallStats.pps_current as number) || 0;
  const cpuUsage = (firewallStats.cpu_usage as number) || 0;
  const memoryUsage = (firewallStats.memory_usage as number) || 0;

  // Elite pie chart data
  const pieData = [
    {
      name: 'Blocked',
      value: packetsDropped,
      color: '#f44336'
    },
    {
      name: 'Allowed', 
      value: packetsPassed,
      color: '#4caf50'
    }
  ];

  // Elite chart updates
  useEffect(() => {
    if (data?.data?.firewall_stats) {
      const newDataPoint = {
        time: new Date().toLocaleTimeString(),
        blocked: packetsDropped,
        allowed: packetsPassed,
        pps: ppsCurrently,
      };

      setChartData(prev => {
        const updated = [...prev, newDataPoint];
        return updated.slice(-20); // Keep last 20 points
      });
    }
  }, [data, packetsDropped, packetsPassed, ppsCurrently]);

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom color="text.primary" sx={{ fontWeight: 'bold' }}>
        🔥 VPP eBPF Firewall Dashboard
      </Typography>

      {/* Elite Connection Status */}
      {!isConnected && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          <strong>WebSocket Disconnected</strong> - Real-time updates unavailable
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Elite Status Overview */}
        <Grid item xs={12}>
          <FirewallStatusCard />
        </Grid>

        {/* Elite Metrics Row */}
        <Grid item xs={12} sm={6} md={3}>
          <StatsCard
            title="Blocked Packets"
            value={packetsDropped}
            icon={<Block />}
            color="error"
          />
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <StatsCard
            title="Allowed Packets"
            value={packetsPassed}
            icon={<CheckCircle />}
            color="success"
          />
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <StatsCard
            title="Total Packets"
            value={packetsTotal}
            icon={<NetworkCheck />}
            color="info"
          />
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <StatsCard
            title="Current PPS"
            value={ppsCurrently.toFixed(1)}
            subtitle="packets/sec"
            icon={<Speed />}
            color="primary"
          />
        </Grid>

        {/* Elite Network Interface */}
        <Grid item xs={12}>
          <NetworkInterfaceCard />
        </Grid>

        {/* Elite System Info */}
        <Grid item xs={12}>
          <SystemInfoCard />
        </Grid>

        {/* Elite Firewall Configuration */}
        <Grid item xs={12}>
          <FirewallConfigurationPanel />
        </Grid>

        {/* Elite Charts */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardHeader 
              title="📈 Packet Flow (Real-time)"
              subheader="Live traffic monitoring"
            />
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="time" 
                    tick={{ fontSize: 12 }}
                    interval="preserveStartEnd"
                  />
                  <YAxis tick={{ fontSize: 12 }} />
                  <RechartsTooltip 
                    labelFormatter={(value) => `Time: ${value}`}
                    formatter={(value: any, name: string) => [
                      typeof value === 'number' ? value.toLocaleString() : value,
                      name
                    ]}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="blocked" 
                    stroke="#f44336" 
                    strokeWidth={2}
                    name="Blocked"
                  />
                  <Line 
                    type="monotone" 
                    dataKey="allowed" 
                    stroke="#4caf50" 
                    strokeWidth={2}
                    name="Allowed"
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card>
            <CardHeader 
              title="📊 Packet Distribution"
              subheader="Current session totals"
            />
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip 
                    formatter={(value: any) => [
                      typeof value === 'number' ? value.toLocaleString() : value,
                      'Packets'
                    ]}
                  />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Elite Performance Metrics */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader title="⚡ Performance Metrics" />
            <CardContent>
              <Box mb={3}>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                  <Typography variant="body2">CPU Usage</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                    {cpuUsage.toFixed(1)}%
                  </Typography>
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={Math.min(cpuUsage, 100)} 
                  color={cpuUsage > 80 ? 'error' : cpuUsage > 60 ? 'warning' : 'success'}
                />
              </Box>
              
              <Box>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                  <Typography variant="body2">Memory Usage</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                    {(memoryUsage / 1024 / 1024).toFixed(1)} MB
                  </Typography>
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={Math.min((memoryUsage / 1024 / 1024 / 1024) * 100, 100)} 
                  color="info"
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardHeader title="🎯 Quick Actions" />
            <CardContent>
              <QuickActionsPanel />
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Container>
  );
};

export default Dashboard; 