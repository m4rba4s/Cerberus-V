// VPP eBPF Firewall Dashboard - Settings Interface
// Enterprise-grade system configuration and management

import React, { useState, useEffect } from 'react';
import { Box, Grid, Typography, Switch, FormControlLabel, Select, MenuItem, FormControl, InputLabel, TextField, Button, Chip, Alert, AlertTitle, Slider, Tabs, Tab, Accordion, AccordionSummary, AccordionDetails, List, ListItem, ListItemIcon, ListItemText, ListItemSecondaryAction, CircularProgress, Tooltip } from '@mui/material';
import { Security, Save, Restore, Download, ExpandMore, Warning, VpnLock, Router, Computer, Dashboard, ColorLens, Language, Build, DataUsage, CheckCircle, Notifications, Shield, Error as ErrorIcon } from '@mui/icons-material';
import { useWebSocket } from '../contexts/WebSocketContext';

// (removed unused SETTINGS_COLORS and SettingsSection)

interface SystemConfig {
  vpp: {
    enabled: boolean;
    workers: number;
    heapSize: string;
    logLevel: string;
    plugins: string[];
  };
  ebpf: {
    enabled: boolean;
    interface: string;
    engine_state?: 'auto' | 'xdp' | 'tc';
    queueId: number;
    verbose: boolean;
    maps: {
      maxEntries: number;
      autoCleanup: boolean;
    };
  };
  security: {
    authEnabled: boolean;
    sessionTimeout: number;
    maxLoginAttempts: number;
    encryption: string;
    certificates: {
      autoRenew: boolean;
      keySize: number;
    };
  };
  monitoring: {
    realTime: boolean;
    retentionDays: number;
    metricsInterval: number;
    alerting: boolean;
    exportFormat: string;
  };
  ui: {
    theme: string;
    language: string;
    refreshInterval: number;
    animations: boolean;
    density: string;
  };
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`settings-tabpanel-${index}`}
      aria-labelledby={`settings-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

const SettingsPage: React.FC = () => {
  const { data } = useWebSocket();
  
  // Primary interface source: WS firewall.interface → current config → recommended from API
  const wsIface = (data as any)?.firewall?.interface as string | undefined;
  
  // State management
  const [currentTab, setCurrentTab] = useState(0);
  const [config, setConfig] = useState<SystemConfig>({
    vpp: {
      enabled: true,
      workers: 4,
      heapSize: '1G',
      logLevel: 'info',
      plugins: ['ebpf-classify', 'acl', 'nat']
    },
    ebpf: {
      enabled: true,
      interface: 'eth0',
      engine_state: 'auto',
      queueId: 0,
      verbose: false,
      maps: {
        maxEntries: 65536,
        autoCleanup: true
      }
    },
    security: {
      authEnabled: false,
      sessionTimeout: 3600,
      maxLoginAttempts: 5,
      encryption: 'AES256',
      certificates: {
        autoRenew: true,
        keySize: 2048
      }
    },
    monitoring: {
      realTime: true,
      retentionDays: 30,
      metricsInterval: 2000,
      alerting: true,
      exportFormat: 'JSON'
    },
    ui: {
      theme: 'light',
      language: 'en',
      refreshInterval: 5000,
      animations: true,
      density: 'standard'
    }
  });
  
  // Update interface when WebSocket data changes
  useEffect(() => {
    const next = wsIface;
    if (next) {
      setConfig(prev => {
        const chosen = { ...prev, ebpf: { ...prev.ebpf, interface: next } } as SystemConfig;
        // If Wi‑Fi is selected and mode is auto or xdp, force TC for safety
        const selected = ifaceList.find(i => i.name === next);
        if (selected?.type === 'wireless') {
          const forced = (prev.ebpf.engine_state === 'xdp' || prev.ebpf.engine_state === 'auto') ? 'tc' : prev.ebpf.engine_state;
          return { ...chosen, ebpf: { ...chosen.ebpf, engine_state: forced || 'tc' } };
        }
        return chosen;
      });
    }
  }, [wsIface]);
  
  // Load current backend config on mount
  useEffect(() => {
    const loadConfig = async () => {
      try {
        const res = await fetch('/api/settings');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (json && json.config) {
          setConfig(json.config as SystemConfig);
          setUnsavedChanges(false);
        }
      } catch (e) {
        // keep defaults on error
        // console.warn('Failed to load settings:', e);
      }
    };
    loadConfig();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Fetch interfaces for dropdown (portable via backend API)
  useEffect(() => {
    const fetchIfaces = async () => {
      setIfaceLoading(true);
      setIfaceError(null);
      try {
        const res = await fetch('/api/network/interfaces');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        const interfaces = (json.interfaces || []) as Array<{name: string; type: string; is_up: boolean; is_default: boolean; ip_addresses: string[];}>;
        setIfaceList(interfaces);
        if (interfaces.length > 0 && !config.ebpf.interface) {
          setConfig(prev => ({
            ...prev,
            ebpf: { ...prev.ebpf, interface: json.recommended?.name || interfaces[0].name }
          }));
        }
      } catch (e: any) {
        setIfaceError(e?.message || 'Failed to load interfaces');
      } finally {
        setIfaceLoading(false);
      }
    };
    fetchIfaces();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  
  const [unsavedChanges, setUnsavedChanges] = useState(false);
  // (remove unused dialog state)
  const [isLoading, setIsLoading] = useState(false);
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');
  const [ifaceList, setIfaceList] = useState<Array<{name: string; type: string; is_up: boolean; is_default: boolean; ip_addresses: string[];}>>([]);
  const [ifaceLoading, setIfaceLoading] = useState(false);
  const [ifaceError, setIfaceError] = useState<string | null>(null);

  // Settings sections
  // (remove unused settingsSections placeholder)

  // Handle configuration changes
  const updateConfig = (section: keyof SystemConfig, field: string, value: any) => {
    setConfig(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        [field]: value
      }
    }));
    setUnsavedChanges(true);
  };

  const updateNestedConfig = (section: keyof SystemConfig, subsection: 'maps' | 'certificates', field: string, value: any) => {
    setConfig(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [subsection]: {
          // @ts-expect-error nested dynamic
          ...prev[section][subsection],
          [field]: value
        }
      }
    }));
    setUnsavedChanges(true);
  };

  // Save configuration
  const saveConfiguration = async () => {
    setSaveStatus('saving');
    setIsLoading(true);
    
    try {
      // REAL API call to backend
      const response = await fetch('/api/settings', { 
        method: 'POST', 
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(config) 
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const result = await response.json();
      console.log('✅ Config saved:', result);
      
      setSaveStatus('success');
      setUnsavedChanges(false);
      // re-load from backend to reflect persisted values (e.g., heapSize 2G)
      try {
        const res = await fetch('/api/settings');
        if (res.ok) {
          const json = await res.json();
          if (json && json.config) setConfig(json.config as SystemConfig);
        }
      } catch (_) {}
      
      // Auto-reset status after 3 seconds
      setTimeout(() => setSaveStatus('idle'), 3000);
    } catch (error) {
      console.error('❌ Save failed:', error);
      setSaveStatus('error');
      setTimeout(() => setSaveStatus('idle'), 3000);
    } finally {
      setIsLoading(false);
    }
  };

  // Reset to defaults
  const resetToDefaults = () => {
    setConfig({
      vpp: {
        enabled: true,
        workers: 4,
        heapSize: '1G',
        logLevel: 'info',
        plugins: ['ebpf-classify', 'acl', 'nat']
      },
      ebpf: {
        enabled: true,
        interface: wsIface || (ifaceList.find(i=>i.is_default)?.name || ifaceList[0]?.name || 'eth0'),
        queueId: 0,
        verbose: false,
        maps: {
          maxEntries: 65536,
          autoCleanup: true
        }
      },
      security: {
        authEnabled: false,
        sessionTimeout: 3600,
        maxLoginAttempts: 5,
        encryption: 'AES256',
        certificates: {
          autoRenew: true,
          keySize: 2048
        }
      },
      monitoring: {
        realTime: true,
        retentionDays: 30,
        metricsInterval: 2000,
        alerting: true,
        exportFormat: 'JSON'
      },
      ui: {
        theme: 'light',
        language: 'en',
        refreshInterval: 5000,
        animations: true,
        density: 'standard'
      }
    });
    setUnsavedChanges(true);
  };

  // Export configuration
  const exportConfiguration = () => {
    const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `firewall_config_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Box sx={{ p: 3, minHeight: '100vh' }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" sx={{ fontWeight: 'bold', color: 'primary.main' }}>
          ⚙️ System Settings
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          {unsavedChanges && (
            <Chip 
              icon={<Warning />}
              label="Unsaved Changes"
              color="warning"
              variant="outlined"
            />
          )}
          <Button
            variant="outlined"
            startIcon={<Download />}
            onClick={exportConfiguration}
            size="small"
          >
            Export Config
          </Button>
          <Button
            variant="outlined"
            startIcon={<Restore />}
            onClick={resetToDefaults}
            size="small"
          >
            Reset Defaults
          </Button>
          <Button
            variant="contained"
            startIcon={<Save />}
            onClick={saveConfiguration}
            disabled={!unsavedChanges || isLoading}
            color={saveStatus === 'success' ? 'success' : saveStatus === 'error' ? 'error' : 'primary'}
          >
            {isLoading ? 'Saving...' : saveStatus === 'success' ? 'Saved!' : saveStatus === 'error' ? 'Error' : 'Save Changes'}
          </Button>
        </Box>
      </Box>

      {/* Save Status Alert */}
      {saveStatus === 'success' && (
        <Alert severity="success" sx={{ mb: 3 }}>
          <AlertTitle>Configuration Saved</AlertTitle>
          All settings have been applied successfully.
        </Alert>
      )}
      
      {saveStatus === 'error' && (
        <Alert severity="error" sx={{ mb: 3 }}>
          <AlertTitle>Save Failed</AlertTitle>
          Failed to save configuration. Please try again.
        </Alert>
      )}

      {/* Settings Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs 
          value={currentTab} 
          onChange={(_, newValue) => setCurrentTab(newValue)}
          variant="fullWidth"
        >
          <Tab icon={<Computer />} label="System" />
          <Tab icon={<Security />} label="Security" />
          <Tab icon={<Dashboard />} label="Monitoring" />
          <Tab icon={<ColorLens />} label="Interface" />
        </Tabs>
      </Box>

      {/* System Configuration Tab */}
      <TabPanel value={currentTab} index={0}>
        <Grid container spacing={3}>
          {/* VPP Configuration */}
          <Grid item xs={12} md={6}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <Router sx={{ mr: 1, color: 'primary.main' }} />
                🔧 VPP Engine Configuration
              </Typography>
              
              <Box sx={{ mb: 3 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.vpp.enabled}
                      onChange={(e) => updateConfig('vpp', 'enabled', e.target.checked)}
                      color="primary"
                    />
                  }
                  label="Enable VPP Engine"
                />
              </Box>

              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <TextField
                    label="Worker Threads"
                    type="number"
                    value={config.vpp.workers}
                    onChange={(e) => updateConfig('vpp', 'workers', parseInt(e.target.value))}
                    fullWidth
                    variant="outlined"
                    disabled={!config.vpp.enabled}
                  />
                </Grid>
                <Grid item xs={6}>
                  <FormControl fullWidth disabled={!config.vpp.enabled}>
                    <InputLabel>Heap Size</InputLabel>
                    <Select
                      value={config.vpp.heapSize}
                      onChange={(e) => updateConfig('vpp', 'heapSize', e.target.value)}
                      label="Heap Size"
                    >
                      <MenuItem value="512M">512 MB</MenuItem>
                      <MenuItem value="1G">1 GB</MenuItem>
                      <MenuItem value="2G">2 GB</MenuItem>
                      <MenuItem value="4G">4 GB</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12}>
                  <FormControl fullWidth disabled={!config.vpp.enabled}>
                    <InputLabel>Log Level</InputLabel>
                    <Select
                      value={config.vpp.logLevel}
                      onChange={(e) => updateConfig('vpp', 'logLevel', e.target.value)}
                      label="Log Level"
                    >
                      <MenuItem value="debug">Debug</MenuItem>
                      <MenuItem value="info">Info</MenuItem>
                      <MenuItem value="warning">Warning</MenuItem>
                      <MenuItem value="error">Error</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>

              <Typography variant="subtitle1" sx={{ mt: 3, mb: 2 }}>
                Enabled Plugins
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                {config.vpp.plugins.map((plugin) => (
                  <Chip
                    key={plugin}
                    label={plugin}
                    color="primary"
                    variant="outlined"
                    disabled={!config.vpp.enabled}
                  />
                ))}
              </Box>
            </Box>
          </Grid>

          {/* eBPF Configuration */}
          <Grid item xs={12} md={6}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <Shield sx={{ mr: 1, color: 'primary.main' }} />
                🛡️ eBPF Datapath Configuration
              </Typography>
              
              <Box sx={{ mb: 3 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.ebpf.enabled}
                      onChange={(e) => updateConfig('ebpf', 'enabled', e.target.checked)}
                      color="primary"
                    />
                  }
                  label="Enable eBPF Datapath"
                />
              </Box>

              <Grid container spacing={2}>
                <Grid item xs={8}>
                  <FormControl fullWidth disabled={!config.ebpf.enabled || ifaceLoading}>
                    <InputLabel>Network Interface</InputLabel>
                    <Select
                      value={config.ebpf.interface}
                      label="Network Interface"
                      onChange={(e) => updateConfig('ebpf', 'interface', e.target.value)}
                    >
                      {ifaceList.map((i) => (
                        <MenuItem key={i.name} value={i.name}>
                          {i.name} {i.is_default ? '(default)' : ''} {i.is_up ? '' : '(down)'} {i.type === 'wireless' ? '— Wi‑Fi (XDP generic only, not recommended)' : ''}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                  <Box sx={{ mt: 0.5, display: 'flex', alignItems: 'center', gap: 1 }}>
                    {ifaceLoading && <CircularProgress size={14} />}
                    <Typography variant="caption" color="text.secondary">
                      Current: {wsIface || config.ebpf.interface || (ifaceList.find(i=>i.is_default)?.name || ifaceList[0]?.name || 'eth0')}
                    </Typography>
                    {ifaceError && (
                      <Typography variant="caption" color="error.main">{ifaceError}</Typography>
                    )}
                  </Box>
                </Grid>
                <Grid item xs={4}>
                  <TextField
                    label="Queue ID"
                    type="number"
                    value={config.ebpf.queueId}
                    onChange={(e) => updateConfig('ebpf', 'queueId', parseInt(e.target.value))}
                    fullWidth
                    variant="outlined"
                    disabled={!config.ebpf.enabled}
                  />
                </Grid>
              </Grid>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth disabled={!config.ebpf.enabled}>
                    <InputLabel>Datapath Mode</InputLabel>
                    <Tooltip title={(ifaceList.find(i => i.name === config.ebpf.interface)?.type === 'wireless') ? 'Wi‑Fi поддерживает только XDP-generic. Рекомендуется режим TC.' : 'auto подберёт лучший режим (XDP для ethernet, TC для Wi‑Fi)'}>
                      <Select
                        value={config.ebpf.engine_state || 'auto'}
                        label="Datapath Mode"
                        onChange={(e) => updateConfig('ebpf', 'engine_state', e.target.value)}
                      >
                        <MenuItem value="auto">auto (recommended)</MenuItem>
                        <MenuItem value="xdp" disabled={ifaceList.find(i => i.name === config.ebpf.interface)?.type === 'wireless'}>xdp (wired NICs)</MenuItem>
                        <MenuItem value="tc">tc (Wi‑Fi safe)</MenuItem>
                      </Select>
                    </Tooltip>
                  </FormControl>
                </Grid>
              </Grid>
              {/* Auto select TC when Wi‑Fi is chosen */}
              {!!config.ebpf.interface && ifaceList.find(i => i.name === config.ebpf.interface && i.type === 'wireless') && (
                <Alert severity="warning" sx={{ mt: 1 }}>
                  Wi‑Fi supports only XDP-generic; performance not guaranteed. Datapath will default to TC for stability.
                </Alert>
              )}

              <Box sx={{ mt: 3 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.ebpf.verbose}
                      onChange={(e) => updateConfig('ebpf', 'verbose', e.target.checked)}
                      color="primary"
                      disabled={!config.ebpf.enabled}
                    />
                  }
                  label="Verbose Logging"
                />
              </Box>

              <Typography variant="subtitle1" sx={{ mt: 3, mb: 2 }}>
                BPF Maps Configuration
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={8}>
                  <TextField
                    label="Max Entries"
                    type="number"
                    value={config.ebpf.maps.maxEntries}
                    onChange={(e) => updateNestedConfig('ebpf', 'maps', 'maxEntries', parseInt(e.target.value))}
                    fullWidth
                    variant="outlined"
                    disabled={!config.ebpf.enabled}
                  />
                </Grid>
                <Grid item xs={4}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={config.ebpf.maps.autoCleanup}
                        onChange={(e) => updateNestedConfig('ebpf', 'maps', 'autoCleanup', e.target.checked)}
                        color="primary"
                        disabled={!config.ebpf.enabled}
                      />
                    }
                    label="Auto Cleanup"
                  />
                </Grid>
              </Grid>
            </Box>
          </Grid>

          {/* System Status */}
          <Grid item xs={12}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <Computer sx={{ mr: 1, color: 'primary.main' }} />
                📊 System Status
              </Typography>
              
              <Grid container spacing={3}>
                <Grid item xs={3}>
                  <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
                    <Typography variant="h4" color="success.main">
                      ACTIVE
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Dual Protection
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={3}>
                  <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
                    <Typography variant="h4" color="primary.main">
                      DUAL PROTECTION
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      VPP Status
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={3}>
                  <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
                    <Typography variant="h4" color="warning.main">
                      15,295
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Packets Processed
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={3}>
                  <Box sx={{ textAlign: 'center', p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
                    <Typography variant="h4" color="error.main">
                      125
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Packets Dropped
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </Box>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Security Configuration Tab */}
      <TabPanel value={currentTab} index={1}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <VpnLock sx={{ mr: 1, color: 'primary.main' }} />
                🔒 Authentication & Access
              </Typography>
              
              <Box sx={{ mb: 3 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.security.authEnabled}
                      onChange={(e) => updateConfig('security', 'authEnabled', e.target.checked)}
                      color="primary"
                    />
                  }
                  label="Enable Authentication"
                />
              </Box>

              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    Session Timeout (seconds)
                  </Typography>
                  <Slider
                    value={config.security.sessionTimeout}
                    onChange={(_, value) => updateConfig('security', 'sessionTimeout', value)}
                    min={300}
                    max={86400}
                    step={300}
                    marks={[
                      { value: 300, label: '5m' },
                      { value: 3600, label: '1h' },
                      { value: 86400, label: '24h' }
                    ]}
                    valueLabelDisplay="auto"
                    disabled={!config.security.authEnabled}
                  />
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    label="Max Login Attempts"
                    type="number"
                    value={config.security.maxLoginAttempts}
                    onChange={(e) => updateConfig('security', 'maxLoginAttempts', parseInt(e.target.value))}
                    fullWidth
                    variant="outlined"
                    disabled={!config.security.authEnabled}
                  />
                </Grid>
                <Grid item xs={12}>
                  <FormControl fullWidth disabled={!config.security.authEnabled}>
                    <InputLabel>Encryption Method</InputLabel>
                    <Select
                      value={config.security.encryption}
                      onChange={(e) => updateConfig('security', 'encryption', e.target.value)}
                      label="Encryption Method"
                    >
                      <MenuItem value="AES128">AES-128</MenuItem>
                      <MenuItem value="AES256">AES-256</MenuItem>
                      <MenuItem value="ChaCha20">ChaCha20</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>
            </Box>
          </Grid>

          <Grid item xs={12} md={6}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <Shield sx={{ mr: 1, color: 'primary.main' }} />
                📄 Certificate Management
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={config.security.certificates.autoRenew}
                        onChange={(e) => updateNestedConfig('security', 'certificates', 'autoRenew', e.target.checked)}
                        color="primary"
                      />
                    }
                    label="Auto-renew Certificates"
                  />
                </Grid>
                <Grid item xs={6}>
                  <FormControl fullWidth>
                    <InputLabel>Key Size</InputLabel>
                    <Select
                      value={config.security.certificates.keySize}
                      onChange={(e) => updateNestedConfig('security', 'certificates', 'keySize', e.target.value)}
                      label="Key Size"
                    >
                      <MenuItem value={1024}>1024 bits</MenuItem>
                      <MenuItem value={2048}>2048 bits</MenuItem>
                      <MenuItem value={4096}>4096 bits</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>

              <Typography variant="subtitle1" sx={{ mt: 2, mb: 1 }}>
                Certificate Status
              </Typography>
              <List>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircle color="success" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="SSL Certificate" 
                    secondary="Valid until 2025-12-31"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <Warning color="warning" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="API Certificate" 
                    secondary="Expires in 30 days"
                  />
                </ListItem>
              </List>
            </Box>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Monitoring Configuration Tab */}
      <TabPanel value={currentTab} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <DataUsage sx={{ mr: 1, color: 'primary.main' }} />
                📊 Data Collection
              </Typography>
              
              <Box sx={{ mb: 3 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.monitoring.realTime}
                      onChange={(e) => updateConfig('monitoring', 'realTime', e.target.checked)}
                      color="primary"
                    />
                  }
                  label="Real-time Monitoring"
                />
              </Box>

              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    Metrics Interval (ms)
                  </Typography>
                  <Slider
                    value={config.monitoring.metricsInterval}
                    onChange={(_, value) => updateConfig('monitoring', 'metricsInterval', value)}
                    min={1000}
                    max={10000}
                    step={1000}
                    marks={[
                      { value: 1000, label: '1s' },
                      { value: 5000, label: '5s' },
                      { value: 10000, label: '10s' }
                    ]}
                    valueLabelDisplay="auto"
                    disabled={!config.monitoring.realTime}
                  />
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    label="Data Retention (days)"
                    type="number"
                    value={config.monitoring.retentionDays}
                    onChange={(e) => updateConfig('monitoring', 'retentionDays', parseInt(e.target.value))}
                    fullWidth
                    variant="outlined"
                  />
                </Grid>
                <Grid item xs={12}>
                  <FormControl fullWidth>
                    <InputLabel>Export Format</InputLabel>
                    <Select
                      value={config.monitoring.exportFormat}
                      onChange={(e) => updateConfig('monitoring', 'exportFormat', e.target.value)}
                      label="Export Format"
                    >
                      <MenuItem value="JSON">JSON</MenuItem>
                      <MenuItem value="CSV">CSV</MenuItem>
                      <MenuItem value="XML">XML</MenuItem>
                      <MenuItem value="Prometheus">Prometheus</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>
            </Box>
          </Grid>

          <Grid item xs={12} md={6}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <Notifications sx={{ mr: 1, color: 'primary.main' }} />
                🔔 Alerts & Notifications
              </Typography>
              
              <Box sx={{ mb: 3 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={config.monitoring.alerting}
                      onChange={(e) => updateConfig('monitoring', 'alerting', e.target.checked)}
                      color="primary"
                    />
                  }
                  label="Enable Alerting"
                />
              </Box>

              <Typography variant="subtitle1" sx={{ mb: 1 }}>
                Alert Channels
              </Typography>
              <List>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircle color="success" />
                  </ListItemIcon>
                  <ListItemText primary="Email Notifications" />
                  <ListItemSecondaryAction>
                    <Switch defaultChecked color="primary" />
                  </ListItemSecondaryAction>
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <ErrorIcon color="disabled" />
                  </ListItemIcon>
                  <ListItemText primary="Slack Integration" />
                  <ListItemSecondaryAction>
                    <Switch color="primary" />
                  </ListItemSecondaryAction>
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <ErrorIcon color="disabled" />
                  </ListItemIcon>
                  <ListItemText primary="Webhook" />
                  <ListItemSecondaryAction>
                    <Switch color="primary" />
                  </ListItemSecondaryAction>
                </ListItem>
              </List>
            </Box>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Interface Configuration Tab */}
      <TabPanel value={currentTab} index={3}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <ColorLens sx={{ mr: 1, color: 'primary.main' }} />
                🎨 Appearance
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <FormControl fullWidth>
                    <InputLabel>Theme</InputLabel>
                    <Select
                      value={config.ui.theme}
                      onChange={(e) => updateConfig('ui', 'theme', e.target.value)}
                      label="Theme"
                    >
                      <MenuItem value="light">Light</MenuItem>
                      <MenuItem value="dark">Dark</MenuItem>
                      <MenuItem value="auto">Auto</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  <FormControl fullWidth>
                    <InputLabel>Density</InputLabel>
                    <Select
                      value={config.ui.density}
                      onChange={(e) => updateConfig('ui', 'density', e.target.value)}
                      label="Density"
                    >
                      <MenuItem value="compact">Compact</MenuItem>
                      <MenuItem value="standard">Standard</MenuItem>
                      <MenuItem value="comfortable">Comfortable</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={config.ui.animations}
                        onChange={(e) => updateConfig('ui', 'animations', e.target.checked)}
                        color="primary"
                      />
                    }
                    label="Enable Animations"
                  />
                </Grid>
              </Grid>
            </Box>
          </Grid>

          <Grid item xs={12} md={6}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <Language sx={{ mr: 1, color: 'primary.main' }} />
                🌐 Localization
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <FormControl fullWidth>
                    <InputLabel>Language</InputLabel>
                    <Select
                      value={config.ui.language}
                      onChange={(e) => updateConfig('ui', 'language', e.target.value)}
                      label="Language"
                    >
                      <MenuItem value="en">English</MenuItem>
                      <MenuItem value="ru">Русский</MenuItem>
                      <MenuItem value="de">Deutsch</MenuItem>
                      <MenuItem value="fr">Français</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    Refresh Interval (ms)
                  </Typography>
                  <Slider
                    value={config.ui.refreshInterval}
                    onChange={(_, value) => updateConfig('ui', 'refreshInterval', value)}
                    min={1000}
                    max={30000}
                    step={1000}
                    marks={[
                      { value: 1000, label: '1s' },
                      { value: 5000, label: '5s' },
                      { value: 30000, label: '30s' }
                    ]}
                    valueLabelDisplay="auto"
                  />
                </Grid>
              </Grid>
            </Box>
          </Grid>

          {/* Advanced Settings */}
          <Grid item xs={12}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <Build sx={{ mr: 1, color: 'primary.main' }} />
                🔧 Advanced Configuration
              </Typography>
              
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography>Developer Tools</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <FormControlLabel
                    control={<Switch color="primary" />}
                    label="Enable Debug Mode"
                  />
                  <FormControlLabel
                    control={<Switch color="primary" />}
                    label="Show Performance Metrics"
                  />
                  <FormControlLabel
                    control={<Switch color="primary" />}
                    label="Enable Console Logging"
                  />
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMore />}>
                  <Typography>Experimental Features</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <FormControlLabel
                    control={<Switch color="primary" />}
                    label="AI-powered Threat Detection"
                  />
                  <FormControlLabel
                    control={<Switch color="primary" />}
                    label="Automatic Rule Optimization"
                  />
                  <FormControlLabel
                    control={<Switch color="primary" />}
                    label="Machine Learning Analytics"
                  />
                </AccordionDetails>
              </Accordion>
            </Box>
          </Grid>
        </Grid>
      </TabPanel>
    </Box>
  );
};

export default SettingsPage; 