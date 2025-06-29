// SPDX-License-Identifier: Apache-2.0
// Professional Firewall Configuration Management

import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Tabs,
  Tab,
  Fab,
  Checkbox,
  Menu,
  ListItemIcon,
  ListItemText,
  Divider,
  Alert,
  Snackbar,
  Tooltip,
  Card,
  CardContent,
  CardActions,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  MoreVert as MoreVertIcon,
  Security as SecurityIcon,
  NetworkCheck as NetworkIcon,
  Policy as PolicyIcon,
  Download as DownloadIcon,
  Upload as UploadIcon,
  FilterList as FilterIcon,
  Search as SearchIcon,
  PlayArrow as EnableIcon,
  Pause as DisableIcon,
  ContentCopy as CopyIcon,
  ExpandMore as ExpandMoreIcon,
  Visibility as ViewIcon,
  VisibilityOff as HideIcon,
  Star as StarIcon,
  Label as TagIcon
} from '@mui/icons-material';
import { useWebSocket } from '../contexts/WebSocketContext';

interface FirewallRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  source_ip: string;
  source_port: string;
  dest_ip: string;
  dest_port: string;
  protocol: string;
  action: string;
  log_enabled: boolean;
  tags: string[];
  created_at: string;
  modified_at: string;
  created_by: string;
}

interface NetworkObject {
  id: string;
  name: string;
  type: string;
  value: string;
  description: string;
  tags: string[];
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
      id={`config-tabpanel-${index}`}
      aria-labelledby={`config-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const Configuration: React.FC = () => {
  const { data, isConnected } = useWebSocket();
  
  // State management
  const [currentTab, setCurrentTab] = useState(0);
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [networkObjects, setNetworkObjects] = useState<NetworkObject[]>([]);
  const [selectedRules, setSelectedRules] = useState<string[]>([]);
  const [filterText, setFilterText] = useState('');
  const [filterProtocol, setFilterProtocol] = useState('all');
  const [filterAction, setFilterAction] = useState('all');
  const [filterEnabled, setFilterEnabled] = useState('all');
  
  // Dialog states
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false);
  const [objectDialogOpen, setObjectDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<FirewallRule | null>(null);
  const [editingObject, setEditingObject] = useState<NetworkObject | null>(null);
  
  // Menu states
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedRuleId, setSelectedRuleId] = useState<string>('');
  
  // Notification state
  const [notification, setNotification] = useState<{open: boolean, message: string, severity: 'success' | 'error' | 'warning' | 'info'}>({
    open: false,
    message: '',
    severity: 'info'
  });
  
  // Form state for new/edit rule
  const [ruleForm, setRuleForm] = useState<Partial<FirewallRule>>({
    name: '',
    description: '',
    enabled: true,
    priority: 100,
    source_ip: 'any',
    source_port: 'any',
    dest_ip: 'any',
    dest_port: 'any',
    protocol: 'any',
    action: 'allow',
    log_enabled: false,
    tags: []
  });
  
  // Form state for network objects
  const [objectForm, setObjectForm] = useState<Partial<NetworkObject>>({
    name: '',
    type: 'host',
    value: '',
    description: '',
    tags: []
  });

  // Load data on component mount
  useEffect(() => {
    loadFirewallRules();
    loadNetworkObjects();
  }, []);

  const loadFirewallRules = async () => {
    try {
      const response = await fetch('/api/firewall/rules');
      if (response.ok) {
        const data = await response.json();
        setRules(data);
      }
    } catch (error) {
      console.error('Error loading firewall rules:', error);
      showNotification('Error loading firewall rules', 'error');
    }
  };

  const loadNetworkObjects = async () => {
    try {
      const response = await fetch('/api/network/objects');
      if (response.ok) {
        const data = await response.json();
        setNetworkObjects(data);
      }
    } catch (error) {
      console.error('Error loading network objects:', error);
      showNotification('Error loading network objects', 'error');
    }
  };

  const showNotification = (message: string, severity: 'success' | 'error' | 'warning' | 'info') => {
    setNotification({ open: true, message, severity });
  };

  const handleCreateRule = async () => {
    try {
      const response = await fetch('/api/firewall/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ruleForm)
      });
      
      if (response.ok) {
        showNotification('Rule created successfully', 'success');
        setRuleDialogOpen(false);
        resetRuleForm();
        loadFirewallRules();
      } else {
        const error = await response.json();
        showNotification(error.detail || 'Error creating rule', 'error');
      }
    } catch (error) {
      showNotification('Error creating rule', 'error');
    }
  };

  const handleUpdateRule = async () => {
    if (!editingRule) return;
    
    try {
      const response = await fetch(`/api/firewall/rules/${editingRule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ruleForm)
      });
      
      if (response.ok) {
        showNotification('Rule updated successfully', 'success');
        setRuleDialogOpen(false);
        setEditingRule(null);
        resetRuleForm();
        loadFirewallRules();
      } else {
        const error = await response.json();
        showNotification(error.detail || 'Error updating rule', 'error');
      }
    } catch (error) {
      showNotification('Error updating rule', 'error');
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    try {
      const response = await fetch(`/api/firewall/rules/${ruleId}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        showNotification('Rule deleted successfully', 'success');
        loadFirewallRules();
      } else {
        showNotification('Error deleting rule', 'error');
      }
    } catch (error) {
      showNotification('Error deleting rule', 'error');
    }
  };

  const handleToggleRule = async (ruleId: string) => {
    try {
      const response = await fetch(`/api/firewall/rules/${ruleId}/toggle`, {
        method: 'POST'
      });
      
      if (response.ok) {
        showNotification('Rule toggled successfully', 'success');
        loadFirewallRules();
      } else {
        showNotification('Error toggling rule', 'error');
      }
    } catch (error) {
      showNotification('Error toggling rule', 'error');
    }
  };

  const handleBulkAction = async (action: string) => {
    if (selectedRules.length === 0) {
      showNotification('No rules selected', 'warning');
      return;
    }

    try {
      const response = await fetch('/api/firewall/rules/bulk-action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, rule_ids: selectedRules })
      });
      
      if (response.ok) {
        showNotification(`Bulk ${action} completed successfully`, 'success');
        setSelectedRules([]);
        loadFirewallRules();
      } else {
        showNotification(`Error performing bulk ${action}`, 'error');
      }
    } catch (error) {
      showNotification(`Error performing bulk ${action}`, 'error');
    }
  };

  const resetRuleForm = () => {
    setRuleForm({
      name: '',
      description: '',
      enabled: true,
      priority: 100,
      source_ip: 'any',
      source_port: 'any',
      dest_ip: 'any',
      dest_port: 'any',
      protocol: 'any',
      action: 'allow',
      log_enabled: false,
      tags: []
    });
  };

  const openEditRuleDialog = (rule: FirewallRule) => {
    setEditingRule(rule);
    setRuleForm({
      name: rule.name,
      description: rule.description,
      enabled: rule.enabled,
      priority: rule.priority,
      source_ip: rule.source_ip,
      source_port: rule.source_port,
      dest_ip: rule.dest_ip,
      dest_port: rule.dest_port,
      protocol: rule.protocol,
      action: rule.action,
      log_enabled: rule.log_enabled,
      tags: rule.tags
    });
    setRuleDialogOpen(true);
  };

  const filteredRules = rules.filter(rule => {
    const matchesText = rule.name.toLowerCase().includes(filterText.toLowerCase()) ||
                       rule.description.toLowerCase().includes(filterText.toLowerCase()) ||
                       rule.source_ip.includes(filterText) ||
                       rule.dest_ip.includes(filterText);
    
    const matchesProtocol = filterProtocol === 'all' || rule.protocol === filterProtocol;
    const matchesAction = filterAction === 'all' || rule.action === filterAction;
    const matchesEnabled = filterEnabled === 'all' || 
                          (filterEnabled === 'enabled' && rule.enabled) ||
                          (filterEnabled === 'disabled' && !rule.enabled);
    
    return matchesText && matchesProtocol && matchesAction && matchesEnabled;
  });

  const handleExportConfig = async () => {
    try {
      const response = await fetch('/api/config/export');
      if (response.ok) {
        const config = await response.json();
        const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `firewall-config-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showNotification('Configuration exported successfully', 'success');
      }
    } catch (error) {
      showNotification('Error exporting configuration', 'error');
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 'bold', color: '#1976d2' }}>
          🛡️ Firewall Configuration
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={handleExportConfig}
          >
            Export Config
          </Button>
          <Button
            variant="outlined"
            startIcon={<UploadIcon />}
            component="label"
          >
            Import Config
            <input type="file" hidden accept=".json" />
          </Button>
        </Box>
      </Box>

      {/* Status Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="primary">Total Rules</Typography>
              <Typography variant="h4">{rules.length}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="success.main">Enabled Rules</Typography>
              <Typography variant="h4">{rules.filter(r => r.enabled).length}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="warning.main">Disabled Rules</Typography>
              <Typography variant="h4">{rules.filter(r => !r.enabled).length}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card>
            <CardContent>
              <Typography variant="h6" color="info.main">Network Objects</Typography>
              <Typography variant="h4">{networkObjects.length}</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Main Content */}
      <Paper sx={{ width: '100%' }}>
        <Tabs
          value={currentTab}
          onChange={(_, newValue) => setCurrentTab(newValue)}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab icon={<SecurityIcon />} label="Firewall Rules" />
          <Tab icon={<NetworkIcon />} label="Network Objects" />
          <Tab icon={<PolicyIcon />} label="Security Policies" />
        </Tabs>

        {/* Firewall Rules Tab */}
        <TabPanel value={currentTab} index={0}>
          {/* Filters and Actions */}
          <Box sx={{ mb: 3, display: 'flex', gap: 2, flexWrap: 'wrap', alignItems: 'center' }}>
            <TextField
              placeholder="Search rules..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              InputProps={{
                startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />
              }}
              sx={{ minWidth: 200 }}
            />
            
            <FormControl sx={{ minWidth: 120 }}>
              <InputLabel>Protocol</InputLabel>
              <Select
                value={filterProtocol}
                onChange={(e) => setFilterProtocol(e.target.value)}
                label="Protocol"
              >
                <MenuItem value="all">All</MenuItem>
                <MenuItem value="tcp">TCP</MenuItem>
                <MenuItem value="udp">UDP</MenuItem>
                <MenuItem value="icmp">ICMP</MenuItem>
                <MenuItem value="any">Any</MenuItem>
              </Select>
            </FormControl>

            <FormControl sx={{ minWidth: 120 }}>
              <InputLabel>Action</InputLabel>
              <Select
                value={filterAction}
                onChange={(e) => setFilterAction(e.target.value)}
                label="Action"
              >
                <MenuItem value="all">All</MenuItem>
                <MenuItem value="allow">Allow</MenuItem>
                <MenuItem value="deny">Deny</MenuItem>
                <MenuItem value="drop">Drop</MenuItem>
                <MenuItem value="reject">Reject</MenuItem>
              </Select>
            </FormControl>

            <FormControl sx={{ minWidth: 120 }}>
              <InputLabel>Status</InputLabel>
              <Select
                value={filterEnabled}
                onChange={(e) => setFilterEnabled(e.target.value)}
                label="Status"
              >
                <MenuItem value="all">All</MenuItem>
                <MenuItem value="enabled">Enabled</MenuItem>
                <MenuItem value="disabled">Disabled</MenuItem>
              </Select>
            </FormControl>

            <Box sx={{ flexGrow: 1 }} />

            {selectedRules.length > 0 && (
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Button
                  variant="outlined"
                  color="success"
                  onClick={() => handleBulkAction('enable')}
                  startIcon={<EnableIcon />}
                >
                  Enable ({selectedRules.length})
                </Button>
                <Button
                  variant="outlined"
                  color="warning"
                  onClick={() => handleBulkAction('disable')}
                  startIcon={<DisableIcon />}
                >
                  Disable ({selectedRules.length})
                </Button>
                <Button
                  variant="outlined"
                  color="error"
                  onClick={() => handleBulkAction('delete')}
                  startIcon={<DeleteIcon />}
                >
                  Delete ({selectedRules.length})
                </Button>
              </Box>
            )}
          </Box>

          {/* Rules Table */}
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell padding="checkbox">
                    <Checkbox
                      indeterminate={selectedRules.length > 0 && selectedRules.length < rules.length}
                      checked={rules.length > 0 && selectedRules.length === rules.length}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedRules(rules.map(r => r.id));
                        } else {
                          setSelectedRules([]);
                        }
                      }}
                    />
                  </TableCell>
                  <TableCell>Priority</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell>Destination</TableCell>
                  <TableCell>Protocol</TableCell>
                  <TableCell>Action</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Tags</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredRules.map((rule) => (
                  <TableRow key={rule.id} hover>
                    <TableCell padding="checkbox">
                      <Checkbox
                        checked={selectedRules.includes(rule.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedRules([...selectedRules, rule.id]);
                          } else {
                            setSelectedRules(selectedRules.filter(id => id !== rule.id));
                          }
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.priority}
                        size="small"
                        color={rule.priority <= 50 ? 'error' : rule.priority <= 100 ? 'warning' : 'default'}
                      />
                    </TableCell>
                    <TableCell>
                      <Box>
                        <Typography variant="body2" fontWeight="bold">{rule.name}</Typography>
                        {rule.description && (
                          <Typography variant="caption" color="text.secondary">
                            {rule.description}
                          </Typography>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box>
                        <Typography variant="body2">{rule.source_ip}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Port: {rule.source_port}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box>
                        <Typography variant="body2">{rule.dest_ip}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Port: {rule.dest_port}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.protocol.toUpperCase()}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.action.toUpperCase()}
                        size="small"
                        color={rule.action === 'allow' ? 'success' : 'error'}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.enabled ? 'Enabled' : 'Disabled'}
                        size="small"
                        color={rule.enabled ? 'success' : 'default'}
                      />
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {rule.tags.map((tag, index) => (
                          <Chip key={index} label={tag} size="small" variant="outlined" />
                        ))}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Tooltip title={rule.enabled ? 'Disable' : 'Enable'}>
                          <IconButton
                            size="small"
                            onClick={() => handleToggleRule(rule.id)}
                            color={rule.enabled ? 'warning' : 'success'}
                          >
                            {rule.enabled ? <DisableIcon /> : <EnableIcon />}
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Edit">
                          <IconButton
                            size="small"
                            onClick={() => openEditRuleDialog(rule)}
                            color="primary"
                          >
                            <EditIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            onClick={() => handleDeleteRule(rule.id)}
                            color="error"
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {filteredRules.length === 0 && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="h6" color="text.secondary">
                No firewall rules found
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Create your first firewall rule to get started
              </Typography>
            </Box>
          )}
        </TabPanel>

        {/* Network Objects Tab */}
        <TabPanel value={currentTab} index={1}>
          <Typography variant="h6" sx={{ mb: 2 }}>Network Objects</Typography>
          <Typography variant="body2" color="text.secondary">
            Network objects allow you to define reusable IP addresses, networks, and ranges.
          </Typography>
          {/* Network objects content would go here */}
        </TabPanel>

        {/* Security Policies Tab */}
        <TabPanel value={currentTab} index={2}>
          <Typography variant="h6" sx={{ mb: 2 }}>Security Policies</Typography>
          <Typography variant="body2" color="text.secondary">
            Security policies group related firewall rules for easier management.
          </Typography>
          {/* Security policies content would go here */}
        </TabPanel>
      </Paper>

      {/* Floating Action Button */}
      <Fab
        color="primary"
        aria-label="add"
        sx={{ position: 'fixed', bottom: 16, right: 16 }}
        onClick={() => {
          resetRuleForm();
          setEditingRule(null);
          setRuleDialogOpen(true);
        }}
      >
        <AddIcon />
      </Fab>

      {/* Rule Dialog */}
      <Dialog
        open={ruleDialogOpen}
        onClose={() => setRuleDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {editingRule ? 'Edit Firewall Rule' : 'Create New Firewall Rule'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Rule Name"
                value={ruleForm.name || ''}
                onChange={(e) => setRuleForm({...ruleForm, name: e.target.value})}
                required
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Priority"
                type="number"
                value={ruleForm.priority || 100}
                onChange={(e) => setRuleForm({...ruleForm, priority: parseInt(e.target.value)})}
                inputProps={{ min: 1, max: 1000 }}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                value={ruleForm.description || ''}
                onChange={(e) => setRuleForm({...ruleForm, description: e.target.value})}
                multiline
                rows={2}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Source IP/CIDR"
                value={ruleForm.source_ip || 'any'}
                onChange={(e) => setRuleForm({...ruleForm, source_ip: e.target.value})}
                placeholder="192.168.1.0/24 or any"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Source Port"
                value={ruleForm.source_port || 'any'}
                onChange={(e) => setRuleForm({...ruleForm, source_port: e.target.value})}
                placeholder="80, 80-90, or any"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Destination IP/CIDR"
                value={ruleForm.dest_ip || 'any'}
                onChange={(e) => setRuleForm({...ruleForm, dest_ip: e.target.value})}
                placeholder="10.0.0.0/8 or any"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Destination Port"
                value={ruleForm.dest_port || 'any'}
                onChange={(e) => setRuleForm({...ruleForm, dest_port: e.target.value})}
                placeholder="443, 80-90, or any"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Protocol</InputLabel>
                <Select
                  value={ruleForm.protocol || 'any'}
                  onChange={(e) => setRuleForm({...ruleForm, protocol: e.target.value})}
                  label="Protocol"
                >
                  <MenuItem value="any">Any</MenuItem>
                  <MenuItem value="tcp">TCP</MenuItem>
                  <MenuItem value="udp">UDP</MenuItem>
                  <MenuItem value="icmp">ICMP</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Action</InputLabel>
                <Select
                  value={ruleForm.action || 'allow'}
                  onChange={(e) => setRuleForm({...ruleForm, action: e.target.value})}
                  label="Action"
                >
                  <MenuItem value="allow">Allow</MenuItem>
                  <MenuItem value="deny">Deny</MenuItem>
                  <MenuItem value="drop">Drop</MenuItem>
                  <MenuItem value="reject">Reject</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Switch
                    checked={ruleForm.enabled || true}
                    onChange={(e) => setRuleForm({...ruleForm, enabled: e.target.checked})}
                  />
                }
                label="Enable Rule"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={ruleForm.log_enabled || false}
                    onChange={(e) => setRuleForm({...ruleForm, log_enabled: e.target.checked})}
                  />
                }
                label="Enable Logging"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRuleDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={editingRule ? handleUpdateRule : handleCreateRule}
            variant="contained"
          >
            {editingRule ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Notification Snackbar */}
      <Snackbar
        open={notification.open}
        autoHideDuration={6000}
        onClose={() => setNotification({...notification, open: false})}
      >
        <Alert
          onClose={() => setNotification({...notification, open: false})}
          severity={notification.severity}
          sx={{ width: '100%' }}
        >
          {notification.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Configuration; 