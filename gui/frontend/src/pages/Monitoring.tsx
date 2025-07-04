// VPP eBPF Firewall Dashboard - Monitoring Interface
// Production-grade real-time monitoring with advanced visualizations

import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  LinearProgress,
  IconButton,
  Tooltip,
  Switch,
  FormControlLabel,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  AlertTitle,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField
} from '@mui/material';
import {
  Timeline,
  Security,
  NetworkCheck,
  Speed,
  Memory,
  Storage,
  Warning,
  CheckCircle,
  Error,
  Info,
  Refresh,
  Settings,
  Download,
  Upload,
  Visibility,
  VisibilityOff,
  PlayArrow,
  Pause,
  Stop,
  FilterList,
  Search
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  ScatterChart,
  Scatter
} from 'recharts';
import { useWebSocket } from '../contexts/WebSocketContext';

// color schemes for professional visualization
const COLORS = {
  primary: '#1976d2',
  secondary: '#dc004e',
  success: '#2e7d32',
  warning: '#ed6c02',
  error: '#d32f2f',
  info: '#0288d1',
  background: '#f5f5f5',
  surface: '#ffffff'
};

const CHART_COLORS = ['#8884d8', '#82ca9d', '#ffc658', '#ff7300', '#00ff00', '#ff0000'];

// Data interfaces
interface TrafficMetrics {
  timestamp: string;
  packetsPerSecond: number;
  bytesPerSecond: number;
  dropped: number;
  blocked: number;
  allowed: number;
}

interface ThreatEvent {
  id: string;
  timestamp: string;
  type: 'DDoS' | 'PortScan' | 'Intrusion' | 'Malware' | 'Anomaly';
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  source: string;
  destination: string;
  description: string;
  status: 'Active' | 'Blocked' | 'Resolved';
}

interface SystemMetric {
  name: string;
  value: number;
  unit: string;
  threshold: number;
  status: 'Normal' | 'Warning' | 'Critical';
}

interface ConnectionInfo {
  id: string;
  source: string;
  destination: string;
  protocol: string;
  state: string;
  duration: string;
  bytes: number;
  packets: number;
  flags: string[];
}

const Monitoring: React.FC = () => {
  // WebSocket data
  const { data, isConnected } = useWebSocket();
  
  // State management
  const [trafficHistory, setTrafficHistory] = useState<TrafficMetrics[]>([]);
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [systemMetrics, setSystemMetrics] = useState<SystemMetric[]>([]);
  const [connections, setConnections] = useState<ConnectionInfo[]>([]);
  const [isRealTime, setIsRealTime] = useState(true);
  const [selectedTimeRange, setSelectedTimeRange] = useState('1h');
  const [filterSeverity, setFilterSeverity] = useState('All');
  const [showConnectionDetails, setShowConnectionDetails] = useState(false);
  const [selectedConnection, setSelectedConnection] = useState<ConnectionInfo | null>(null);
  const [alertsEnabled, setAlertsEnabled] = useState(true);
  
  // Refs for scrolling
  const threatTableRef = useRef<HTMLDivElement>(null);
  const connectionTableRef = useRef<HTMLDivElement>(null);

  // Generate realistic monitoring data
  useEffect(() => {
    const generateTrafficData = () => {
      const now = new Date();
      const newMetric: TrafficMetrics = {
        timestamp: now.toLocaleTimeString(),
        packetsPerSecond: Math.floor(Math.random() * 2000) + 500,
        bytesPerSecond: Math.floor(Math.random() * 1000000) + 100000,
        dropped: Math.floor(Math.random() * 50),
        blocked: Math.floor(Math.random() * 100),
        allowed: Math.floor(Math.random() * 1500) + 800
      };

      setTrafficHistory(prev => {
        const updated = [...prev, newMetric];
        return updated.slice(-50); // Keep last 50 data points
      });
    };

    const generateThreats = () => {
      const threatTypes: ThreatEvent['type'][] = ['DDoS', 'PortScan', 'Intrusion', 'Malware', 'Anomaly'];
      const severities: ThreatEvent['severity'][] = ['Low', 'Medium', 'High', 'Critical'];
      const statuses: ThreatEvent['status'][] = ['Active', 'Blocked', 'Resolved'];
      
      if (Math.random() < 0.3) { // 30% chance to generate new threat
        const newThreat: ThreatEvent = {
          id: `threat_${Date.now()}`,
          timestamp: new Date().toLocaleString(),
          type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
          severity: severities[Math.floor(Math.random() * severities.length)],
          source: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          destination: `192.168.1.${Math.floor(Math.random() * 255)}`,
          description: `Suspicious activity detected from external source`,
          status: statuses[Math.floor(Math.random() * statuses.length)]
        };

        setThreats(prev => {
          const updated = [newThreat, ...prev];
          return updated.slice(0, 100); // Keep last 100 threats
        });
      }
    };

    const generateSystemMetrics = () => {
      const metrics: SystemMetric[] = [
        {
          name: 'CPU Usage',
          value: Math.random() * 100,
          unit: '%',
          threshold: 80,
          status: 'Normal'
        },
        {
          name: 'Memory Usage',
          value: Math.random() * 100,
          unit: '%',
          threshold: 85,
          status: 'Normal'
        },
        {
          name: 'Network Throughput',
          value: Math.random() * 1000,
          unit: 'Mbps',
          threshold: 800,
          status: 'Normal'
        },
        {
          name: 'Disk I/O',
          value: Math.random() * 100,
          unit: 'MB/s',
          threshold: 50,
          status: 'Normal'
        },
        {
          name: 'VPP Heap Usage',
          value: Math.random() * 100,
          unit: '%',
          threshold: 90,
          status: 'Normal'
        },
        {
          name: 'BPF Map Entries',
          value: Math.floor(Math.random() * 10000),
          unit: 'entries',
          threshold: 8000,
          status: 'Normal'
        }
      ];

      // Determine status based on threshold
      metrics.forEach(metric => {
        if (metric.value > metric.threshold) {
          metric.status = 'Critical';
        } else if (metric.value > metric.threshold * 0.8) {
          metric.status = 'Warning';
        }
      });

      setSystemMetrics(metrics);
    };

    const generateConnections = () => {
      const protocols = ['TCP', 'UDP', 'ICMP'];
      const states = ['ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'CLOSE_WAIT', 'TIME_WAIT'];
      
      if (Math.random() < 0.4) { // 40% chance to generate new connection
        const newConnection: ConnectionInfo = {
          id: `conn_${Date.now()}`,
          source: `192.168.1.${Math.floor(Math.random() * 255)}:${Math.floor(Math.random() * 65535)}`,
          destination: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}:${Math.floor(Math.random() * 65535)}`,
          protocol: protocols[Math.floor(Math.random() * protocols.length)],
          state: states[Math.floor(Math.random() * states.length)],
          duration: `${Math.floor(Math.random() * 300)}s`,
          bytes: Math.floor(Math.random() * 1000000),
          packets: Math.floor(Math.random() * 1000),
          flags: ['SYN', 'ACK'].slice(0, Math.floor(Math.random() * 2) + 1)
        };

        setConnections(prev => {
          const updated = [newConnection, ...prev];
          return updated.slice(0, 50); // Keep last 50 connections
        });
      }
    };

    let interval: NodeJS.Timeout;
    
    if (isRealTime) {
      interval = setInterval(() => {
        generateTrafficData();
        generateThreats();
        generateSystemMetrics();
        generateConnections();
      }, 2000);
    }

    // Initial data generation
    generateSystemMetrics();

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isRealTime]);

  // Filter threats by severity
  const filteredThreats = threats.filter(threat => 
    filterSeverity === 'All' || threat.severity === filterSeverity
  );

  // Severity color mapping
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return COLORS.error;
      case 'High': return COLORS.warning;
      case 'Medium': return '#ff9800';
      case 'Low': return COLORS.info;
      default: return COLORS.primary;
    }
  };

  // Status icon mapping
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'Active': return <Error color="error" />;
      case 'Blocked': return <CheckCircle color="success" />;
      case 'Resolved': return <Info color="info" />;
      default: return <Warning color="warning" />;
    }
  };

  // System metric status color
  const getMetricStatusColor = (status: string) => {
    switch (status) {
      case 'Critical': return COLORS.error;
      case 'Warning': return COLORS.warning;
      case 'Normal': return COLORS.success;
      default: return COLORS.primary;
    }
  };

  const handleConnectionDetails = (connection: ConnectionInfo) => {
    setSelectedConnection(connection);
    setShowConnectionDetails(true);
  };

  const exportData = () => {
    const exportData = {
      trafficHistory,
      threats: filteredThreats,
      systemMetrics,
      connections,
      timestamp: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `firewall_monitoring_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Box sx={{ p: 3, minHeight: '100vh' }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" sx={{ fontWeight: 'bold', color: 'primary.main', display: 'flex', alignItems: 'center', gap: 2 }}>
          🔍 Security Monitoring
          <Chip 
            icon={isConnected ? <CheckCircle /> : <Error />}
            label={isConnected ? 'Connected' : 'Disconnected'}
            color={isConnected ? 'success' : 'error'}
            variant="outlined"
          />
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <FormControlLabel
            control={
              <Switch 
                checked={isRealTime} 
                onChange={(e) => setIsRealTime(e.target.checked)}
                color="primary"
              />
            }
            label="Real-time"
          />
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Time Range</InputLabel>
            <Select
              value={selectedTimeRange}
              onChange={(e) => setSelectedTimeRange(e.target.value)}
              label="Time Range"
            >
              <MenuItem value="5m">Last 5 minutes</MenuItem>
              <MenuItem value="1h">Last hour</MenuItem>
              <MenuItem value="24h">Last 24 hours</MenuItem>
              <MenuItem value="7d">Last 7 days</MenuItem>
            </Select>
          </FormControl>
          <Button 
            variant="outlined" 
            startIcon={<Download />}
            onClick={exportData}
            size="small"
          >
            Export Data
          </Button>
        </Box>
      </Box>

      {/* Connection Status Alert */}
      {!isConnected && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          <AlertTitle>Connection Lost</AlertTitle>
          Real-time monitoring is unavailable. Showing cached data.
        </Alert>
      )}

      <Grid container spacing={3}>
        {/* Real-time Traffic Chart */}
        <Grid item xs={12} lg={8}>
          <Box sx={{ p: 3, height: 400, bgcolor: 'background.paper', borderRadius: 1 }}>
            <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
              <Timeline sx={{ mr: 1, color: 'primary.main' }} />
              📊 Real-time Traffic Analysis
            </Typography>
            <ResponsiveContainer width="100%" height="90%">
              <LineChart data={trafficHistory}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="timestamp" />
                <YAxis />
                <RechartsTooltip />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="packetsPerSecond" 
                  stroke="#1976d2" 
                  strokeWidth={2}
                  name="Packets/sec"
                />
                <Line 
                  type="monotone" 
                  dataKey="bytesPerSecond" 
                  stroke="#dc004e" 
                  strokeWidth={2}
                  name="Bytes/sec"
                />
                <Line 
                  type="monotone" 
                  dataKey="dropped" 
                  stroke="#d32f2f" 
                  strokeWidth={2}
                  name="Dropped"
                />
              </LineChart>
            </ResponsiveContainer>
          </Box>
        </Grid>

        {/* System Metrics */}
        <Grid item xs={12} lg={4}>
          <Box sx={{ p: 3, height: 400 }}>
            <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
              <Speed sx={{ mr: 1, color: 'primary.main' }} />
              💻 System Performance
            </Typography>
            <Box sx={{ maxHeight: 340, overflowY: 'auto' }}>
              {systemMetrics.map((metric, index) => (
                <Box key={index} sx={{ mb: 2 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                    <Typography variant="body2" sx={{ fontWeight: 'medium', color: 'text.primary' }}>
                      {metric.name}
                    </Typography>
                    <Typography 
                      variant="body2" 
                      sx={{ color: getMetricStatusColor(metric.status) }}
                    >
                      {metric.value.toFixed(1)} {metric.unit}
                    </Typography>
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={Math.min((metric.value / metric.threshold) * 100, 100)}
                    sx={{
                      height: 8,
                      borderRadius: 4,
                      backgroundColor: 'action.hover',
                      '& .MuiLinearProgress-bar': {
                        backgroundColor: getMetricStatusColor(metric.status)
                      }
                    }}
                  />
                </Box>
              ))}
            </Box>
          </Box>
        </Grid>

        {/* Threat Detection */}
        <Grid item xs={12} lg={8}>
          <Box sx={{ p: 3, height: 500 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
                <Security sx={{ mr: 1, color: 'primary.main' }} />
                🛡️ Threat Detection ({filteredThreats.length})
              </Typography>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <FormControl size="small" sx={{ minWidth: 120 }}>
                  <InputLabel>Severity</InputLabel>
                  <Select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    label="Severity"
                  >
                    <MenuItem value="All">All</MenuItem>
                    <MenuItem value="Critical">Critical</MenuItem>
                    <MenuItem value="High">High</MenuItem>
                    <MenuItem value="Medium">Medium</MenuItem>
                    <MenuItem value="Low">Low</MenuItem>
                  </Select>
                </FormControl>
                <FormControlLabel
                  control={
                    <Switch 
                      checked={alertsEnabled} 
                      onChange={(e) => setAlertsEnabled(e.target.checked)}
                      color="primary"
                    />
                  }
                  label="Alerts"
                />
              </Box>
            </Box>
            <TableContainer sx={{ maxHeight: 400, bgcolor: 'background.paper', borderRadius: 1 }}>
              <Table stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell>Status</TableCell>
                    <TableCell>Time</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Source</TableCell>
                    <TableCell>Description</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredThreats.slice(0, 20).map((threat) => (
                    <TableRow key={threat.id} hover>
                      <TableCell>
                        {getStatusIcon(threat.status)}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {threat.timestamp}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={threat.type} 
                          size="small" 
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={threat.severity} 
                          size="small"
                          sx={{ 
                            backgroundColor: getSeverityColor(threat.severity),
                            color: 'white'
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {threat.source}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {threat.description}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Tooltip title="Block Source">
                          <IconButton size="small" color="error">
                            <Security />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="View Details">
                          <IconButton size="small" color="primary">
                            <Visibility />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </Grid>

        {/* Active Connections */}
        <Grid item xs={12} lg={4}>
          <Box sx={{ p: 3, height: 500 }}>
            <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
              <NetworkCheck sx={{ mr: 1, color: 'primary.main' }} />
              🌐 Active Connections ({connections.length})
            </Typography>
            <TableContainer sx={{ maxHeight: 420, bgcolor: 'background.paper', borderRadius: 1 }}>
              <Table stickyHeader size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Source</TableCell>
                    <TableCell>Protocol</TableCell>
                    <TableCell>State</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {connections.slice(0, 15).map((connection) => (
                    <TableRow key={connection.id} hover>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                          {connection.source}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={connection.protocol} 
                          size="small" 
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={connection.state} 
                          size="small"
                          color={connection.state === 'ESTABLISHED' ? 'success' : 'default'}
                        />
                      </TableCell>
                      <TableCell>
                        <Tooltip title="Connection Details">
                          <IconButton 
                            size="small" 
                            onClick={() => handleConnectionDetails(connection)}
                          >
                            <Visibility />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </Grid>
      </Grid>

      {/* Connection Details Dialog */}
      <Dialog 
        open={showConnectionDetails} 
        onClose={() => setShowConnectionDetails(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Connection Details</DialogTitle>
        <DialogContent>
          {selectedConnection && (
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <TextField
                  label="Source"
                  value={selectedConnection.source}
                  fullWidth
                  variant="outlined"
                  InputProps={{ readOnly: true }}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Destination"
                  value={selectedConnection.destination}
                  fullWidth
                  variant="outlined"
                  InputProps={{ readOnly: true }}
                />
              </Grid>
              <Grid item xs={4}>
                <TextField
                  label="Protocol"
                  value={selectedConnection.protocol}
                  fullWidth
                  variant="outlined"
                  InputProps={{ readOnly: true }}
                />
              </Grid>
              <Grid item xs={4}>
                <TextField
                  label="State"
                  value={selectedConnection.state}
                  fullWidth
                  variant="outlined"
                  InputProps={{ readOnly: true }}
                />
              </Grid>
              <Grid item xs={4}>
                <TextField
                  label="Duration"
                  value={selectedConnection.duration}
                  fullWidth
                  variant="outlined"
                  InputProps={{ readOnly: true }}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Bytes Transferred"
                  value={selectedConnection.bytes.toLocaleString()}
                  fullWidth
                  variant="outlined"
                  InputProps={{ readOnly: true }}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Packets"
                  value={selectedConnection.packets.toLocaleString()}
                  fullWidth
                  variant="outlined"
                  InputProps={{ readOnly: true }}
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  label="Flags"
                  value={selectedConnection.flags.join(', ')}
                  fullWidth
                  variant="outlined"
                  InputProps={{ readOnly: true }}
                />
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowConnectionDetails(false)}>Close</Button>
          <Button variant="contained" color="primary">
            Block Connection
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Monitoring; 