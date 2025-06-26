// VPP eBPF Firewall Dashboard - Elite Settings Interface
// Enterprise-grade system configuration and management

import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  Switch,
  FormControlLabel,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  TextField,
  Button,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  AlertTitle,
  Slider,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  Badge,
  LinearProgress
} from '@mui/material';
import {
  Settings as SettingsIcon,
  Security,
  NetworkCheck,
  Speed,
  Memory,
  Notifications,
  Save,
  Restore,
  Download,
  Upload,
  Delete,
  Edit,
  Add,
  ExpandMore,
  Warning,
  CheckCircle,
  Error,
  Info,
  Visibility,
  VisibilityOff,
  Shield,
  VpnLock,
  Router,
  Computer,
  Dashboard,
  ColorLens,
  Language,
  Schedule,
  Backup,
  Update,
  Build,
  Code,
  DataUsage,
  FilterList
} from '@mui/icons-material';
import { useWebSocket } from '../contexts/WebSocketContext';

const SETTINGS_COLORS = {
  primary: '#1565c0',
  secondary: '#c62828',
  accent: '#2e7d32',
  warning: '#f57f17',
  error: '#d32f2f',
  info: '#0277bd',
  success: '#388e3c',
  background: '#fafafa',
  surface: '#ffffff'
};

interface SettingsSection {
  id: string;
  title: string;
  icon: React.ReactNode;
  description: string;
}

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
  const { data, isConnected } = useWebSocket();
  
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
      interface: 'wlan0',
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
  
  const [unsavedChanges, setUnsavedChanges] = useState(false);
  const [showBackupDialog, setShowBackupDialog] = useState(false);
  const [showRestoreDialog, setShowRestoreDialog] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');

  // Settings sections
  const settingsSections: SettingsSection[] = [
    {
      id: 'system',
      title: 'System Configuration',
      icon: <Computer color="primary" />,
      description: 'Core system and performance settings'
    },
    {
      id: 'security',
      title: 'Security & Authentication',
      icon: <Security color="primary" />,
      description: 'Security policies and access control'
    },
    {
      id: 'monitoring',
      title: 'Monitoring & Alerts',
      icon: <Dashboard color="primary" />,
      description: 'Monitoring configuration and alerting'
    },
    {
      id: 'interface',
      title: 'User Interface',
      icon: <ColorLens color="primary" />,
      description: 'UI preferences and customization'
    }
  ];

  // Handle configuration changes
  const updateConfig = (section: keyof SystemConfig, field: string, value: any) => {
    setConfig(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [field]: value
      }
    }));
    setUnsavedChanges(true);
  };

  const updateNestedConfig = (section: keyof SystemConfig, subsection: string, field: string, value: any) => {
    setConfig(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [subsection]: {
          ...prev[section][subsection as keyof typeof prev[section]],
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
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Here you would make the actual API call
      // await fetch('/api/settings', { method: 'POST', body: JSON.stringify(config) });
      
      setSaveStatus('success');
      setUnsavedChanges(false);
      
      // Auto-reset status after 3 seconds
      setTimeout(() => setSaveStatus('idle'), 3000);
    } catch (error) {
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
        interface: 'wlan0',
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
    <Box sx={{ p: 3, backgroundColor: SETTINGS_COLORS.background, minHeight: '100vh' }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" sx={{ fontWeight: 'bold', color: SETTINGS_COLORS.primary }}>
          ⚙️ Elite System Settings
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
      <Paper sx={{ mb: 3 }}>
        <Tabs 
          value={currentTab} 
          onChange={(_, newValue) => setCurrentTab(newValue)}
          variant="fullWidth"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab icon={<Computer />} label="System" />
          <Tab icon={<Security />} label="Security" />
          <Tab icon={<Dashboard />} label="Monitoring" />
          <Tab icon={<ColorLens />} label="Interface" />
        </Tabs>

        {/* System Configuration Tab */}
        <TabPanel value={currentTab} index={0}>
          <Grid container spacing={3}>
            {/* VPP Configuration */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Router sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  VPP Engine Configuration
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
                        <MenuItem value="error">Error</MenuItem>
                        <MenuItem value="warn">Warning</MenuItem>
                        <MenuItem value="info">Info</MenuItem>
                        <MenuItem value="debug">Debug</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                </Grid>

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
                  Enabled Plugins
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {config.vpp.plugins.map((plugin) => (
                    <Chip
                      key={plugin}
                      label={plugin}
                      color="primary"
                      variant="outlined"
                      size="small"
                    />
                  ))}
                </Box>
              </Paper>
            </Grid>

            {/* eBPF Configuration */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Shield sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  eBPF Datapath Configuration
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
                  <Grid item xs={6}>
                    <TextField
                      label="Network Interface"
                      value={config.ebpf.interface}
                      onChange={(e) => updateConfig('ebpf', 'interface', e.target.value)}
                      fullWidth
                      variant="outlined"
                      disabled={!config.ebpf.enabled}
                    />
                  </Grid>
                  <Grid item xs={6}>
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
                  <Grid item xs={12}>
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
                  </Grid>
                </Grid>

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
                  BPF Maps Configuration
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
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
                  <Grid item xs={6}>
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
              </Paper>
            </Grid>

            {/* System Status */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Computer sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  System Status
                </Typography>
                
                <Grid container spacing={3}>
                  <Grid item xs={3}>
                    <Card sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h6" color="primary">
                        {data?.dual_protection?.enabled ? 'ACTIVE' : 'INACTIVE'}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Dual Protection
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={3}>
                    <Card sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h6" color="success.main">
                        {data?.dual_protection?.vpp_stats?.status || 'SIMULATION'}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        VPP Status
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={3}>
                    <Card sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h6" color="warning.main">
                        {data?.firewall_stats?.packets_processed?.toLocaleString() || '0'}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Packets Processed
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={3}>
                    <Card sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h6" color="error.main">
                        {data?.firewall_stats?.packets_dropped?.toLocaleString() || '0'}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Packets Dropped
                      </Typography>
                    </Card>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Security Configuration Tab */}
        <TabPanel value={currentTab} index={1}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <VpnLock sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  Authentication & Access
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
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Shield sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  Certificate Management
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

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
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
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Monitoring Configuration Tab */}
        <TabPanel value={currentTab} index={2}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <DataUsage sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  Data Collection
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
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Notifications sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  Alerts & Notifications
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

                <Typography variant="subtitle2" sx={{ mb: 1 }}>
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
                      <Error color="disabled" />
                    </ListItemIcon>
                    <ListItemText primary="Slack Integration" />
                    <ListItemSecondaryAction>
                      <Switch color="primary" />
                    </ListItemSecondaryAction>
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <Error color="disabled" />
                    </ListItemIcon>
                    <ListItemText primary="Webhook" />
                    <ListItemSecondaryAction>
                      <Switch color="primary" />
                    </ListItemSecondaryAction>
                  </ListItem>
                </List>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Interface Configuration Tab */}
        <TabPanel value={currentTab} index={3}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <ColorLens sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  Appearance
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
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Language sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  Localization
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
              </Paper>
            </Grid>

            {/* Advanced Settings */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Build sx={{ mr: 1, color: SETTINGS_COLORS.primary }} />
                  Advanced Configuration
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
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>
      </Paper>

      {/* Backup/Restore Dialog */}
      <Dialog open={showBackupDialog} onClose={() => setShowBackupDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Backup Configuration</DialogTitle>
        <DialogContent>
          <Typography variant="body1">
            Create a backup of your current firewall configuration. This includes all settings, rules, and preferences.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowBackupDialog(false)}>Cancel</Button>
          <Button variant="contained" onClick={() => { exportConfiguration(); setShowBackupDialog(false); }}>
            Create Backup
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default SettingsPage; 