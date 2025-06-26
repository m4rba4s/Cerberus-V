// VPP eBPF Firewall Dashboard - Elite Analytics Interface
// Enterprise-grade security analytics and intelligence platform

import React, { useState, useEffect, useMemo } from 'react';
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
  TextField,
  Tabs,
  Tab,
  Badge,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Avatar,
  CircularProgress
} from '@mui/material';
import {
  Analytics as AnalyticsIcon,
  TrendingUp,
  TrendingDown,
  Assessment,
  Security,
  NetworkCheck,
  Speed,
  Memory,
  Storage,
  Warning,
  CheckCircle,
  Error,
  Info,
  Timeline,
  PieChart,
  BarChart,
  ShowChart,
  FilterList,
  Search,
  Download,
  Refresh,
  LocationOn,
  Language,
  VpnLock,
  Fingerprint,
  BugReport,
  Shield,
  Visibility,
  DataUsage,
  MoreVert
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
  BarChart as RechartsBarChart,
  Bar,
  PieChart as RechartsPieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  Treemap,
  ComposedChart
} from 'recharts';
import { useWebSocket } from '../contexts/WebSocketContext';

// Elite color palette for professional analytics
const ANALYTICS_COLORS = {
  primary: '#1565c0',
  secondary: '#c62828',
  accent: '#2e7d32',
  warning: '#f57f17',
  error: '#d32f2f',
  info: '#0277bd',
  success: '#388e3c',
  background: '#fafafa',
  surface: '#ffffff',
  text: '#212121',
  textSecondary: '#757575'
};

const CHART_PALETTE = [
  '#3f51b5', '#e91e63', '#00bcd4', '#ff9800', 
  '#4caf50', '#9c27b0', '#ff5722', '#607d8b'
];

// Data interfaces for analytics
interface SecurityMetric {
  id: string;
  name: string;
  value: number;
  change: number;
  trend: 'up' | 'down' | 'stable';
  unit: string;
  category: 'threats' | 'performance' | 'traffic' | 'system';
}

interface ThreatIntelligence {
  id: string;
  source: string;
  country: string;
  city: string;
  threats: number;
  severity: number;
  firstSeen: string;
  lastSeen: string;
  attackTypes: string[];
  reputation: 'malicious' | 'suspicious' | 'unknown' | 'trusted';
}

interface NetworkFlow {
  timestamp: string;
  protocol: string;
  sourcePort: number;
  destPort: number;
  bytes: number;
  packets: number;
  flags: string[];
  geo: {
    country: string;
    city: string;
    latitude: number;
    longitude: number;
  };
}

interface PerformanceAnalytics {
  component: string;
  metric: string;
  current: number;
  average: number;
  peak: number;
  efficiency: number;
  bottlenecks: string[];
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
      id={`analytics-tabpanel-${index}`}
      aria-labelledby={`analytics-tab-${index}`}
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

const Analytics: React.FC = () => {
  // WebSocket data
  const { data, isConnected } = useWebSocket();
  
  // State management
  const [currentTab, setCurrentTab] = useState(0);
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetric[]>([]);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelligence[]>([]);
  const [networkFlows, setNetworkFlows] = useState<NetworkFlow[]>([]);
  const [performanceData, setPerformanceData] = useState<PerformanceAnalytics[]>([]);
  const [timeRange, setTimeRange] = useState('24h');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [isLoading, setIsLoading] = useState(false);

  // Add new state for revolutionary analytics
  const [attackTimeline, setAttackTimeline] = useState<any[]>([]);
  const [threatHunting, setThreatHunting] = useState<any>({});
  const [complianceData, setComplianceData] = useState<any>({});
  const [forensicData, setForensicData] = useState<any>({});
  const [aiInsights, setAiInsights] = useState<any>({});

  // Fetch revolutionary analytics data
  const fetchAdvancedAnalytics = async () => {
    try {
      const [timeline, hunting, compliance, forensics, ai] = await Promise.all([
        fetch('/api/analytics/attack-timeline').then(r => r.json()),
        fetch('/api/analytics/threat-hunting').then(r => r.json()),
        fetch('/api/analytics/compliance-dashboard').then(r => r.json()),
        fetch('/api/analytics/forensic-analysis').then(r => r.json()),
        fetch('/api/analytics/ai-insights').then(r => r.json())
      ]);
      
      setAttackTimeline(timeline.attack_timeline || []);
      setThreatHunting(hunting);
      setComplianceData(compliance);
      setForensicData(forensics);
      setAiInsights(ai);
    } catch (error) {
      console.error('Failed to fetch advanced analytics:', error);
    }
  };

  // Generate realistic analytics data
  useEffect(() => {
    const generateSecurityMetrics = () => {
      const metrics: SecurityMetric[] = [
        {
          id: 'threats_blocked',
          name: 'Threats Blocked',
          value: Math.floor(Math.random() * 1000) + 500,
          change: (Math.random() - 0.5) * 20,
          trend: Math.random() > 0.5 ? 'up' : 'down',
          unit: 'threats',
          category: 'threats'
        },
        {
          id: 'attack_attempts',
          name: 'Attack Attempts',
          value: Math.floor(Math.random() * 500) + 200,
          change: (Math.random() - 0.5) * 30,
          trend: Math.random() > 0.3 ? 'up' : 'down',
          unit: 'attempts',
          category: 'threats'
        },
        {
          id: 'bandwidth_usage',
          name: 'Bandwidth Usage',
          value: Math.floor(Math.random() * 100) + 50,
          change: (Math.random() - 0.5) * 10,
          trend: Math.random() > 0.4 ? 'up' : 'down',
          unit: '%',
          category: 'traffic'
        },
        {
          id: 'latency_avg',
          name: 'Average Latency',
          value: Math.random() * 5 + 1,
          change: (Math.random() - 0.5) * 2,
          trend: Math.random() > 0.6 ? 'down' : 'up',
          unit: 'ms',
          category: 'performance'
        },
        {
          id: 'connections_active',
          name: 'Active Connections',
          value: Math.floor(Math.random() * 2000) + 1000,
          change: (Math.random() - 0.5) * 100,
          trend: Math.random() > 0.5 ? 'up' : 'down',
          unit: 'connections',
          category: 'traffic'
        },
        {
          id: 'cpu_efficiency',
          name: 'CPU Efficiency',
          value: Math.floor(Math.random() * 40) + 60,
          change: (Math.random() - 0.5) * 5,
          trend: Math.random() > 0.7 ? 'up' : 'down',
          unit: '%',
          category: 'system'
        }
      ];
      setSecurityMetrics(metrics);
    };

    const generateThreatIntel = () => {
      const countries = ['China', 'Russia', 'Brazil', 'India', 'USA', 'Germany', 'Unknown'];
      const cities = ['Beijing', 'Moscow', 'São Paulo', 'Mumbai', 'New York', 'Berlin', 'Unknown'];
      const attackTypes = ['DDoS', 'Brute Force', 'SQL Injection', 'XSS', 'Port Scan', 'Malware'];
      const reputations: ThreatIntelligence['reputation'][] = ['malicious', 'suspicious', 'unknown', 'trusted'];

      const intel: ThreatIntelligence[] = Array.from({ length: 20 }, (_, i) => ({
        id: `intel_${i}`,
        source: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        country: countries[Math.floor(Math.random() * countries.length)],
        city: cities[Math.floor(Math.random() * cities.length)],
        threats: Math.floor(Math.random() * 100) + 1,
        severity: Math.floor(Math.random() * 10) + 1,
        firstSeen: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toLocaleDateString(),
        lastSeen: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toLocaleDateString(),
        attackTypes: attackTypes.slice(0, Math.floor(Math.random() * 3) + 1),
        reputation: reputations[Math.floor(Math.random() * reputations.length)]
      }));

      setThreatIntel(intel);
    };

    const generateNetworkFlows = () => {
      const protocols = ['TCP', 'UDP', 'ICMP'];
      const countries = ['CN', 'RU', 'BR', 'IN', 'US', 'DE'];

      const flows: NetworkFlow[] = Array.from({ length: 100 }, (_, i) => ({
        timestamp: new Date(Date.now() - i * 60000).toISOString(),
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        sourcePort: Math.floor(Math.random() * 65535),
        destPort: Math.floor(Math.random() * 65535),
        bytes: Math.floor(Math.random() * 1000000),
        packets: Math.floor(Math.random() * 1000),
        flags: ['SYN', 'ACK', 'FIN'].slice(0, Math.floor(Math.random() * 2) + 1),
        geo: {
          country: countries[Math.floor(Math.random() * countries.length)],
          city: 'Unknown',
          latitude: (Math.random() - 0.5) * 180,
          longitude: (Math.random() - 0.5) * 360
        }
      }));

      setNetworkFlows(flows);
    };

    const generatePerformanceData = () => {
      const components = ['VPP Engine', 'eBPF Datapath', 'Control Plane', 'Web Interface'];
      const metrics = ['CPU Usage', 'Memory Usage', 'Throughput', 'Latency'];

      const performance: PerformanceAnalytics[] = components.flatMap(component =>
        metrics.map(metric => ({
          component,
          metric,
          current: Math.random() * 100,
          average: Math.random() * 80 + 10,
          peak: Math.random() * 100 + 80,
          efficiency: Math.random() * 40 + 60,
          bottlenecks: ['Memory allocation', 'Network I/O'].slice(0, Math.floor(Math.random() * 2))
        }))
      );

      setPerformanceData(performance);
    };

    // Initial data generation
    generateSecurityMetrics();
    generateThreatIntel();
    generateNetworkFlows();
    generatePerformanceData();
    
    // Fetch revolutionary analytics
    fetchAdvancedAnalytics();

    // Auto-refresh interval
    let interval: number;
    if (autoRefresh) {
      interval = setInterval(() => {
        setIsLoading(true);
        setTimeout(() => {
          generateSecurityMetrics();
          generateThreatIntel();
          generateNetworkFlows();
          generatePerformanceData();
          fetchAdvancedAnalytics(); // Also refresh advanced analytics
          setIsLoading(false);
        }, 1000);
      }, 30000); // Refresh every 30 seconds
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh]);

  // Computed analytics
  const threatSummary = useMemo(() => {
    const totalThreats = threatIntel.reduce((sum, intel) => sum + intel.threats, 0);
    const uniqueCountries = new Set(threatIntel.map(intel => intel.country)).size;
    const averageSeverity = threatIntel.reduce((sum, intel) => sum + intel.severity, 0) / threatIntel.length;
    const maliciousCount = threatIntel.filter(intel => intel.reputation === 'malicious').length;

    return { totalThreats, uniqueCountries, averageSeverity, maliciousCount };
  }, [threatIntel]);

  const trafficAnalytics = useMemo(() => {
    const protocolDistribution = networkFlows.reduce((acc, flow) => {
      acc[flow.protocol] = (acc[flow.protocol] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const countryDistribution = networkFlows.reduce((acc, flow) => {
      acc[flow.geo.country] = (acc[flow.geo.country] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const totalBytes = networkFlows.reduce((sum, flow) => sum + flow.bytes, 0);
    const totalPackets = networkFlows.reduce((sum, flow) => sum + flow.packets, 0);

    return { protocolDistribution, countryDistribution, totalBytes, totalPackets };
  }, [networkFlows]);

  const getTrendIcon = (trend: 'up' | 'down' | 'stable') => {
    switch (trend) {
      case 'up': return <TrendingUp color="success" />;
      case 'down': return <TrendingDown color="error" />;
      default: return <Timeline color="info" />;
    }
  };

  const getReputationColor = (reputation: string) => {
    switch (reputation) {
      case 'malicious': return ANALYTICS_COLORS.error;
      case 'suspicious': return ANALYTICS_COLORS.warning;
      case 'trusted': return ANALYTICS_COLORS.success;
      default: return ANALYTICS_COLORS.info;
    }
  };

  const exportAnalytics = () => {
    const analyticsData = {
      securityMetrics,
      threatIntel,
      networkFlows: networkFlows.slice(0, 10), // Limit export size
      performanceData,
      summary: {
        threatSummary,
        trafficAnalytics
      },
      timestamp: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(analyticsData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `firewall_analytics_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Box sx={{ p: 3, backgroundColor: ANALYTICS_COLORS.background, minHeight: '100vh' }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h4" sx={{ fontWeight: 'bold', color: ANALYTICS_COLORS.primary }}>
          📊 Elite Security Analytics
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <FormControlLabel
            control={
              <Switch 
                checked={autoRefresh} 
                onChange={(e) => setAutoRefresh(e.target.checked)}
                color="primary"
              />
            }
            label="Auto-refresh"
          />
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Time Range</InputLabel>
            <Select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              label="Time Range"
            >
              <MenuItem value="1h">Last hour</MenuItem>
              <MenuItem value="24h">Last 24 hours</MenuItem>
              <MenuItem value="7d">Last 7 days</MenuItem>
              <MenuItem value="30d">Last 30 days</MenuItem>
            </Select>
          </FormControl>
          <Button 
            variant="outlined" 
            startIcon={<Download />}
            onClick={exportAnalytics}
            size="small"
          >
            Export Analytics
          </Button>
          {isLoading && <CircularProgress size={24} />}
          <Chip 
            icon={isConnected ? <CheckCircle /> : <Error />}
            label={isConnected ? 'Live Data' : 'Cached Data'}
            color={isConnected ? 'success' : 'warning'}
            variant="outlined"
          />
        </Box>
      </Box>

      {/* Key Metrics Overview */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {securityMetrics.slice(0, 6).map((metric) => (
          <Grid item xs={12} sm={6} md={4} lg={2} key={metric.id}>
            <Card sx={{ p: 2, textAlign: 'center', height: '100%' }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                <Typography variant="body2" color="textSecondary">
                  {metric.name}
                </Typography>
                {getTrendIcon(metric.trend)}
              </Box>
              <Typography variant="h4" color="primary" sx={{ mb: 1 }}>
                {metric.value.toLocaleString()}
              </Typography>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
                {metric.unit}
              </Typography>
              <Typography 
                variant="body2" 
                color={metric.change >= 0 ? 'success.main' : 'error.main'}
                sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}
              >
                {metric.change >= 0 ? '+' : ''}{metric.change.toFixed(1)}%
              </Typography>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Analytics Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs 
          value={currentTab} 
          onChange={(_, newValue) => setCurrentTab(newValue)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab 
            icon={<Security />} 
            label="Threat Intelligence" 
            id="analytics-tab-0"
            aria-controls="analytics-tabpanel-0"
          />
          <Tab 
            icon={<Assessment />} 
            label="Traffic Analysis" 
            id="analytics-tab-1"
            aria-controls="analytics-tabpanel-1"
          />
          <Tab 
            icon={<Speed />} 
            label="Performance" 
            id="analytics-tab-2"
            aria-controls="analytics-tabpanel-2"
          />
          <Tab 
            icon={<LocationOn />} 
            label="Geolocation" 
            id="analytics-tab-3"
            aria-controls="analytics-tabpanel-3"
          />
          <Tab 
            icon={<Timeline />} 
            label="🔥 Attack Timeline" 
            id="analytics-tab-4"
            aria-controls="analytics-tabpanel-4"
          />
          <Tab 
            icon={<Search />} 
            label="🕵️ Threat Hunting" 
            id="analytics-tab-5"
            aria-controls="analytics-tabpanel-5"
          />
          <Tab 
            icon={<Assessment />} 
            label="📋 Compliance" 
            id="analytics-tab-6"
            aria-controls="analytics-tabpanel-6"
          />
          <Tab 
            icon={<BugReport />} 
            label="🔬 Forensics" 
            id="analytics-tab-7"
            aria-controls="analytics-tabpanel-7"
          />
          <Tab 
            icon={<Memory />} 
            label="🤖 AI Insights" 
            id="analytics-tab-8"
            aria-controls="analytics-tabpanel-8"
          />
        </Tabs>

        {/* Threat Intelligence Tab */}
        <TabPanel value={currentTab} index={0}>
          <Grid container spacing={3}>
            {/* Threat Summary */}
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Shield sx={{ mr: 1, color: ANALYTICS_COLORS.primary }} />
                  Threat Summary
                </Typography>
                <List>
                  <ListItem>
                    <ListItemIcon>
                      <BugReport color="error" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Total Threats" 
                      secondary={threatSummary.totalThreats.toLocaleString()}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <LocationOn color="warning" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Source Countries" 
                      secondary={threatSummary.uniqueCountries}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <Warning color="error" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Avg Severity" 
                      secondary={`${threatSummary.averageSeverity.toFixed(1)}/10`}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <Error color="error" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Malicious IPs" 
                      secondary={threatSummary.maliciousCount}
                    />
                  </ListItem>
                </List>
              </Paper>
            </Grid>

            {/* Threat Intel Table */}
            <Grid item xs={12} md={8}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Threat Intelligence Feed
                </Typography>
                <TableContainer sx={{ maxHeight: 400 }}>
                  <Table stickyHeader size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Source IP</TableCell>
                        <TableCell>Location</TableCell>
                        <TableCell>Threats</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Reputation</TableCell>
                        <TableCell>Attack Types</TableCell>
                        <TableCell>Last Seen</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {threatIntel.slice(0, 10).map((intel) => (
                        <TableRow key={intel.id} hover>
                          <TableCell sx={{ fontFamily: 'monospace' }}>
                            {intel.source}
                          </TableCell>
                          <TableCell>
                            {intel.country}, {intel.city}
                          </TableCell>
                          <TableCell>
                            <Badge badgeContent={intel.threats} color="error" max={999}>
                              <Security />
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <LinearProgress 
                              variant="determinate" 
                              value={intel.severity * 10} 
                              sx={{ 
                                width: 60,
                                '& .MuiLinearProgress-bar': {
                                  backgroundColor: intel.severity > 7 ? ANALYTICS_COLORS.error : 
                                                 intel.severity > 4 ? ANALYTICS_COLORS.warning : 
                                                 ANALYTICS_COLORS.success
                                }
                              }}
                            />
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={intel.reputation}
                              size="small"
                              sx={{ 
                                backgroundColor: getReputationColor(intel.reputation),
                                color: 'white'
                              }}
                            />
                          </TableCell>
                          <TableCell>
                            {intel.attackTypes.slice(0, 2).map(type => (
                              <Chip 
                                key={type} 
                                label={type} 
                                size="small" 
                                variant="outlined"
                                sx={{ mr: 0.5, mb: 0.5 }}
                              />
                            ))}
                          </TableCell>
                          <TableCell sx={{ fontSize: '0.8rem' }}>
                            {intel.lastSeen}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Traffic Analysis Tab */}
        <TabPanel value={currentTab} index={1}>
          <Grid container spacing={3}>
            {/* Protocol Distribution */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: 400 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Protocol Distribution
                </Typography>
                <ResponsiveContainer width="100%" height="85%">
                  <RechartsPieChart>
                    <Pie
                      data={Object.entries(trafficAnalytics.protocolDistribution).map(([protocol, count]) => ({
                        name: protocol,
                        value: count,
                        fill: CHART_PALETTE[Object.keys(trafficAnalytics.protocolDistribution).indexOf(protocol)]
                      }))}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      dataKey="value"
                    >
                      {Object.entries(trafficAnalytics.protocolDistribution).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={CHART_PALETTE[index]} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                  </RechartsPieChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* Traffic Volume Over Time */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: 400 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Traffic Volume Timeline
                </Typography>
                <ResponsiveContainer width="100%" height="85%">
                  <AreaChart data={networkFlows.slice(-20).reverse()}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="timestamp" tickFormatter={(value) => new Date(value).toLocaleTimeString()} />
                    <YAxis />
                    <RechartsTooltip />
                    <Legend />
                    <Area 
                      type="monotone" 
                      dataKey="bytes" 
                      stackId="1"
                      stroke={ANALYTICS_COLORS.primary} 
                      fill={ANALYTICS_COLORS.primary}
                      name="Bytes"
                    />
                    <Area 
                      type="monotone" 
                      dataKey="packets" 
                      stackId="2"
                      stroke={ANALYTICS_COLORS.secondary} 
                      fill={ANALYTICS_COLORS.secondary}
                      name="Packets"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* Top Ports */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: 350 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Most Active Ports
                </Typography>
                <ResponsiveContainer width="100%" height="85%">
                  <RechartsBarChart 
                    data={[
                      { port: '80', count: 150, name: 'HTTP' },
                      { port: '443', count: 120, name: 'HTTPS' },
                      { port: '22', count: 45, name: 'SSH' },
                      { port: '53', count: 80, name: 'DNS' },
                      { port: '25', count: 30, name: 'SMTP' }
                    ]}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="port" />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="count" fill={ANALYTICS_COLORS.accent} />
                  </RechartsBarChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* Traffic Summary */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: 350 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Traffic Summary
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Card sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="primary">
                        {Math.floor(trafficAnalytics.totalBytes / 1024 / 1024).toLocaleString()}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Total MB
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={6}>
                    <Card sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="secondary">
                        {trafficAnalytics.totalPackets.toLocaleString()}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Total Packets
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={6}>
                    <Card sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="success.main">
                        {Object.keys(trafficAnalytics.protocolDistribution).length}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Protocols
                      </Typography>
                    </Card>
                  </Grid>
                  <Grid item xs={6}>
                    <Card sx={{ p: 2, textAlign: 'center' }}>
                      <Typography variant="h4" color="warning.main">
                        {Object.keys(trafficAnalytics.countryDistribution).length}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Countries
                      </Typography>
                    </Card>
                  </Grid>
                </Grid>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Performance Tab */}
        <TabPanel value={currentTab} index={2}>
          <Grid container spacing={3}>
            {/* Performance Radar Chart */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: 400 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  System Performance Radar
                </Typography>
                <ResponsiveContainer width="100%" height="85%">
                  <RadarChart data={[
                    { subject: 'CPU', A: 80, B: 90, fullMark: 100 },
                    { subject: 'Memory', A: 75, B: 85, fullMark: 100 },
                    { subject: 'Network', A: 95, B: 88, fullMark: 100 },
                    { subject: 'Disk I/O', A: 70, B: 80, fullMark: 100 },
                    { subject: 'Latency', A: 85, B: 78, fullMark: 100 },
                    { subject: 'Throughput', A: 90, B: 92, fullMark: 100 }
                  ]}>
                    <PolarGrid />
                    <PolarAngleAxis dataKey="subject" />
                    <PolarRadiusAxis angle={90} domain={[0, 100]} />
                    <Radar
                      name="Current"
                      dataKey="A"
                      stroke={ANALYTICS_COLORS.primary}
                      fill={ANALYTICS_COLORS.primary}
                      fillOpacity={0.3}
                    />
                    <Radar
                      name="Baseline"
                      dataKey="B"
                      stroke={ANALYTICS_COLORS.secondary}
                      fill={ANALYTICS_COLORS.secondary}
                      fillOpacity={0.3}
                    />
                    <Legend />
                  </RadarChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>

            {/* Component Performance */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: 400 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Component Efficiency
                </Typography>
                <Box sx={{ maxHeight: 320, overflowY: 'auto' }}>
                  {performanceData.slice(0, 8).map((perf, index) => (
                    <Box key={index} sx={{ mb: 2 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                        <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                          {perf.component} - {perf.metric}
                        </Typography>
                        <Typography variant="body2" color="primary">
                          {perf.efficiency.toFixed(1)}%
                        </Typography>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={perf.efficiency}
                        sx={{
                          height: 8,
                          borderRadius: 4,
                          backgroundColor: '#e0e0e0',
                          '& .MuiLinearProgress-bar': {
                            backgroundColor: perf.efficiency > 80 ? ANALYTICS_COLORS.success :
                                           perf.efficiency > 60 ? ANALYTICS_COLORS.warning :
                                           ANALYTICS_COLORS.error
                          }
                        }}
                      />
                    </Box>
                  ))}
                </Box>
              </Paper>
            </Grid>

            {/* VPP vs eBPF Performance */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3, height: 400 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  VPP vs eBPF Performance Comparison
                </Typography>
                <ResponsiveContainer width="100%" height="85%">
                  <ComposedChart data={[
                    { name: 'Packet Processing', vpp: 85000, ebpf: 95000 },
                    { name: 'Memory Usage', vpp: 45, ebpf: 30 },
                    { name: 'CPU Usage', vpp: 35, ebpf: 25 },
                    { name: 'Latency (µs)', vpp: 12, ebpf: 8 },
                    { name: 'Throughput (Gbps)', vpp: 40, ebpf: 100 }
                  ]}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <RechartsTooltip />
                    <Legend />
                    <Bar dataKey="vpp" fill={ANALYTICS_COLORS.primary} name="VPP Engine" />
                    <Bar dataKey="ebpf" fill={ANALYTICS_COLORS.accent} name="eBPF Datapath" />
                  </ComposedChart>
                </ResponsiveContainer>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Geolocation Tab */}
        <TabPanel value={currentTab} index={3}>
          <Grid container spacing={3}>
            {/* Geographic Distribution */}
            <Grid item xs={12} md={8}>
              <Paper sx={{ p: 3, height: 500 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Geographic Threat Distribution
                </Typography>
                <Box sx={{ 
                  height: 400, 
                  backgroundColor: '#f5f5f5', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center',
                  border: '2px dashed #ccc',
                  borderRadius: 2
                }}>
                  <Typography variant="body1" color="textSecondary">
                    🗺️ Interactive World Map<br/>
                    Showing threat sources by country<br/>
                    <small>(Map visualization placeholder)</small>
                  </Typography>
                </Box>
              </Paper>
            </Grid>

            {/* Country Breakdown */}
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: 500 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Top Source Countries
                </Typography>
                <List sx={{ maxHeight: 400, overflowY: 'auto' }}>
                  {Object.entries(trafficAnalytics.countryDistribution)
                    .sort(([,a], [,b]) => b - a)
                    .slice(0, 10)
                    .map(([country, count], index) => (
                    <ListItem key={country}>
                      <ListItemIcon>
                        <Avatar sx={{ 
                          bgcolor: CHART_PALETTE[index % CHART_PALETTE.length],
                          width: 24, 
                          height: 24,
                          fontSize: '0.8rem'
                        }}>
                          {index + 1}
                        </Avatar>
                      </ListItemIcon>
                      <ListItemText 
                        primary={country}
                        secondary={`${count} connections`}
                      />
                      <Typography variant="body2" color="textSecondary">
                        {((count / networkFlows.length) * 100).toFixed(1)}%
                      </Typography>
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Attack Timeline Tab */}
        <TabPanel value={currentTab} index={4}>
          <Grid container spacing={3}>
            {/* Attack Timeline Header */}
            <Grid item xs={12}>
              <Alert severity="info" sx={{ mb: 2 }}>
                <AlertTitle>🔥 Elite Attack Timeline - Real-time Security Chronicle</AlertTitle>
                Live timeline of security events with MITRE ATT&CK mapping and response metrics
              </Alert>
            </Grid>

            {/* Timeline Summary Cards */}
            <Grid item xs={12} md={3}>
              <Card sx={{ p: 2, textAlign: 'center', bgcolor: '#fff3e0' }}>
                <Typography variant="h4" color="warning.main">
                  {attackTimeline.filter(e => e.severity === 'critical').length}
                </Typography>
                <Typography variant="body2">Critical Events</Typography>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card sx={{ p: 2, textAlign: 'center', bgcolor: '#ffebee' }}>
                <Typography variant="h4" color="error.main">
                  {attackTimeline.filter(e => e.severity === 'high').length}
                </Typography>
                <Typography variant="body2">High Priority</Typography>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card sx={{ p: 2, textAlign: 'center', bgcolor: '#e8f5e8' }}>
                <Typography variant="h4" color="success.main">
                  {attackTimeline.filter(e => e.blocked).length}
                </Typography>
                <Typography variant="body2">Blocked Attacks</Typography>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card sx={{ p: 2, textAlign: 'center', bgcolor: '#e3f2fd' }}>
                <Typography variant="h4" color="primary">
                  {attackTimeline.length > 0 ? Math.round(attackTimeline.reduce((sum, e) => sum + e.response_time, 0) / attackTimeline.length) : 0}ms
                </Typography>
                <Typography variant="body2">Avg Response</Typography>
              </Card>
            </Grid>

            {/* Attack Timeline Table */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Timeline sx={{ mr: 1, color: ANALYTICS_COLORS.primary }} />
                  Attack Event Chronicle
                </Typography>
                <TableContainer sx={{ maxHeight: 500 }}>
                  <Table stickyHeader size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Timestamp</TableCell>
                        <TableCell>Attack Type</TableCell>
                        <TableCell>Severity</TableCell>
                        <TableCell>Source IP</TableCell>
                        <TableCell>Target Port</TableCell>
                        <TableCell>MITRE Technique</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Confidence</TableCell>
                        <TableCell>Response Time</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {attackTimeline.slice(0, 20).map((event, index) => (
                        <TableRow key={event.id} hover>
                          <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                            {new Date(event.timestamp).toLocaleString()}
                          </TableCell>
                          <TableCell>
                            <Tooltip title={event.description}>
                              <Chip 
                                label={event.attack_type} 
                                size="small"
                                icon={<Warning />}
                                color={event.severity === 'critical' ? 'error' : 
                                       event.severity === 'high' ? 'warning' : 'default'}
                              />
                            </Tooltip>
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={event.severity.toUpperCase()}
                              size="small"
                              sx={{ 
                                backgroundColor: 
                                  event.severity === 'critical' ? ANALYTICS_COLORS.error :
                                  event.severity === 'high' ? ANALYTICS_COLORS.warning :
                                  event.severity === 'medium' ? '#ff9800' : '#4caf50',
                                color: 'white'
                              }}
                            />
                          </TableCell>
                          <TableCell sx={{ fontFamily: 'monospace' }}>
                            {event.source_ip}
                          </TableCell>
                          <TableCell>
                            <Badge 
                              badgeContent={event.affected_assets} 
                              color="error"
                              anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
                            >
                              <Chip label={event.target_port} size="small" variant="outlined" />
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Tooltip title="MITRE ATT&CK Technique">
                              <Chip 
                                label={event.mitre_technique} 
                                size="small"
                                variant="outlined"
                                color="primary"
                              />
                            </Tooltip>
                          </TableCell>
                          <TableCell>
                            {event.blocked ? (
                              <Chip 
                                icon={<CheckCircle />}
                                label="BLOCKED" 
                                size="small" 
                                color="success"
                              />
                            ) : (
                              <Chip 
                                icon={<Error />}
                                label="ALLOWED" 
                                size="small" 
                                color="error"
                              />
                            )}
                          </TableCell>
                          <TableCell>
                            <LinearProgress 
                              variant="determinate" 
                              value={event.confidence} 
                              sx={{ 
                                width: 60,
                                '& .MuiLinearProgress-bar': {
                                  backgroundColor: event.confidence > 90 ? ANALYTICS_COLORS.success : 
                                                  event.confidence > 75 ? ANALYTICS_COLORS.warning : 
                                                  ANALYTICS_COLORS.error
                                }
                              }}
                            />
                            <Typography variant="caption" sx={{ ml: 1 }}>
                              {event.confidence}%
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography 
                              variant="body2" 
                              color={event.response_time < 500 ? 'success.main' : 
                                     event.response_time < 1000 ? 'warning.main' : 'error.main'}
                            >
                              {event.response_time}ms
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Threat Hunting Tab */}
        <TabPanel value={currentTab} index={5}>
          <Grid container spacing={3}>
            {/* Threat Hunting Header */}
            <Grid item xs={12}>
              <Alert severity="warning" sx={{ mb: 2 }}>
                <AlertTitle>🕵️ Elite Threat Hunting - Advanced IOC Analysis</AlertTitle>
                Proactive threat detection with behavioral analytics and intelligence correlation
              </Alert>
            </Grid>

            {/* Hunting Summary */}
            <Grid item xs={12} md={3}>
              <Card sx={{ p: 2, textAlign: 'center', bgcolor: '#f3e5f5' }}>
                <Typography variant="h4" color="secondary">
                  {threatHunting.hunt_summary?.total_iocs || 0}
                </Typography>
                <Typography variant="body2">Total IOCs</Typography>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card sx={{ p: 2, textAlign: 'center', bgcolor: '#ffebee' }}>
                <Typography variant="h4" color="error.main">
                  {threatHunting.hunt_summary?.critical_threats || 0}
                </Typography>
                <Typography variant="body2">Critical Threats</Typography>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card sx={{ p: 2, textAlign: 'center', bgcolor: '#e8f5e8' }}>
                <Typography variant="h4" color="success.main">
                  {threatHunting.hunt_summary?.active_hunts || 0}
                </Typography>
                <Typography variant="body2">Active Hunts</Typography>
              </Card>
            </Grid>
            <Grid item xs={12} md={3}>
              <Card sx={{ p: 2, textAlign: 'center', bgcolor: '#e3f2fd' }}>
                <Typography variant="h4" color="primary">
                  {threatHunting.hunt_summary?.success_rate || 0}%
                </Typography>
                <Typography variant="body2">Success Rate</Typography>
              </Card>
            </Grid>

            {/* IOCs Table */}
            <Grid item xs={12} md={8}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <Search sx={{ mr: 1, color: ANALYTICS_COLORS.primary }} />
                  Indicators of Compromise (IOCs)
                </Typography>
                <TableContainer sx={{ maxHeight: 400 }}>
                  <Table stickyHeader size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Type</TableCell>
                        <TableCell>Value</TableCell>
                        <TableCell>Threat Level</TableCell>
                        <TableCell>Detections</TableCell>
                        <TableCell>Sources</TableCell>
                        <TableCell>Last Seen</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(threatHunting.iocs || []).slice(0, 15).map((ioc: any) => (
                        <TableRow key={ioc.id} hover>
                          <TableCell>
                            <Chip 
                              label={ioc.type} 
                              size="small"
                              color={ioc.type === 'Hash' ? 'primary' : 
                                     ioc.type === 'IP' ? 'secondary' : 'default'}
                            />
                          </TableCell>
                          <TableCell sx={{ 
                            fontFamily: 'monospace', 
                            fontSize: '0.8rem',
                            maxWidth: 200,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis'
                          }}>
                            <Tooltip title={ioc.value}>
                              <span>{ioc.value}</span>
                            </Tooltip>
                          </TableCell>
                          <TableCell>
                            <Chip 
                              label={ioc.threat_level.toUpperCase()}
                              size="small"
                              sx={{ 
                                backgroundColor: 
                                  ioc.threat_level === 'critical' ? ANALYTICS_COLORS.error :
                                  ioc.threat_level === 'high' ? ANALYTICS_COLORS.warning :
                                  ioc.threat_level === 'medium' ? '#ff9800' : '#4caf50',
                                color: 'white'
                              }}
                            />
                          </TableCell>
                          <TableCell>
                            <Badge badgeContent={ioc.detections} color="error" max={999}>
                              <Fingerprint />
                            </Badge>
                          </TableCell>
                          <TableCell>
                            {ioc.sources.slice(0, 2).map((source: string) => (
                              <Chip 
                                key={source}
                                label={source} 
                                size="small" 
                                variant="outlined"
                                sx={{ mr: 0.5, mb: 0.5 }}
                              />
                            ))}
                          </TableCell>
                          <TableCell sx={{ fontSize: '0.8rem' }}>
                            {ioc.last_seen}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Paper>
            </Grid>

            {/* Behavioral Patterns */}
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                  <BugReport sx={{ mr: 1, color: ANALYTICS_COLORS.warning }} />
                  Behavioral Patterns
                </Typography>
                <List>
                  {(threatHunting.behavioral_patterns || []).map((pattern: any, index: number) => (
                    <ListItem key={index} sx={{ px: 0 }}>
                      <ListItemIcon>
                        <Warning color={pattern.risk_score > 80 ? 'error' : 'warning'} />
                      </ListItemIcon>
                      <ListItemText 
                        primary={pattern.pattern}
                        secondary={
                          <>
                            <Typography variant="body2" color="textSecondary">
                              {pattern.description}
                            </Typography>
                            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                              <Chip 
                                label={`Risk: ${pattern.risk_score}%`}
                                size="small"
                                color={pattern.risk_score > 80 ? 'error' : 'warning'}
                              />
                              <Chip 
                                label={`${pattern.occurrences} events`}
                                size="small"
                                variant="outlined"
                              />
                              <Chip 
                                label={`${pattern.affected_hosts} hosts`}
                                size="small"
                                variant="outlined"
                              />
                            </Box>
                          </>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>

            {/* MITRE ATT&CK Tactics */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" sx={{ mb: 2 }}>
                  MITRE ATT&CK Tactics Coverage
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                  {['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 
                    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 
                    'Collection', 'Command and Control', 'Exfiltration', 'Impact'].map(tactic => (
                    <Chip 
                      key={tactic}
                      label={tactic}
                      variant="outlined"
                      color="primary"
                      sx={{ mb: 1 }}
                    />
                  ))}
                </Box>
              </Paper>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Compliance Tab */}
        <TabPanel value={currentTab} index={6}>
          {/* Implementation of Compliance tab content */}
        </TabPanel>

        {/* Forensics Tab */}
        <TabPanel value={currentTab} index={7}>
          {/* Implementation of Forensics tab content */}
        </TabPanel>

        {/* AI Insights Tab */}
        <TabPanel value={currentTab} index={8}>
          {/* Implementation of AI Insights tab content */}
        </TabPanel>
      </Paper>
    </Box>
  );
};

export default Analytics; 