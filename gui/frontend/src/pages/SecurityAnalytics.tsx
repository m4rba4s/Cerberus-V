import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Chip,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Alert,} from '@mui/material';
import {
  Security,
  TrendingUp,
  TrendingDown,
  Block,
  Visibility,
  Refresh
} from '@mui/icons-material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer } from 'recharts';

interface SecurityMetrics {
  totalThreats: number;
  blockedThreats: number;
  successRate: number;
  avgResponseTime: number;
}

interface Threat {
  ip_address: string;
  threat_type: string;
  severity: string;
  country: string;
  timestamp: string;
}

interface Alert {
  id: string;
  severity: string;
  message: string;
  timestamp: string;
}

const SecurityAnalytics: React.FC = () => {
  const [securityMetrics, setSecurityMetrics] = useState<SecurityMetrics>({
    totalThreats: 0,
    blockedThreats: 0,
    successRate: 0,
    avgResponseTime: 0
  });
  const [threats, setThreats] = useState<Threat[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchSecurityData = async () => {
    try {
      // Simulate API call
      const mockMetrics: SecurityMetrics = {
        totalThreats: 1247,
        blockedThreats: 1198,
        successRate: 96.1,
        avgResponseTime: 2.3
      };

      const mockThreats: Threat[] = [
        { ip_address: '192.168.1.100', threat_type: 'DDoS', severity: 'High', country: 'US', timestamp: '2024-01-15T10:30:00Z' },
        { ip_address: '10.0.0.50', threat_type: 'Port Scan', severity: 'Medium', country: 'CN', timestamp: '2024-01-15T10:25:00Z' },
        { ip_address: '172.16.0.25', threat_type: 'SQL Injection', severity: 'High', country: 'RU', timestamp: '2024-01-15T10:20:00Z' }
      ];

      const mockAlerts: Alert[] = [
        { id: '1', severity: 'High', message: 'DDoS attack detected from 192.168.1.100', timestamp: '2024-01-15T10:30:00Z' },
        { id: '2', severity: 'Medium', message: 'Port scan detected from 10.0.0.50', timestamp: '2024-01-15T10:25:00Z' }
      ];

      setSecurityMetrics(mockMetrics);
      setThreats(mockThreats);
      setAlerts(mockAlerts);
    } catch (error) {
      console.error('Error fetching security data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSecurityData();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'default';
    }
  };

  const chartData = [
    { time: '00:00', threats: 12, blocked: 11 },
    { time: '04:00', threats: 8, blocked: 7 },
    { time: '08:00', threats: 25, blocked: 24 },
    { time: '12:00', threats: 45, blocked: 43 },
    { time: '16:00', threats: 38, blocked: 36 },
    { time: '20:00', threats: 22, blocked: 21 }
  ];

  if (loading) {
    return (
      <Box sx={{ p: 3, display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
        <Typography>Loading security analytics...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ fontFamily: '"JetBrains Mono", monospace', mb: 3 }}>
        🔒 Security Analytics
      </Typography>

      {/* Security Metrics Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ backgroundColor: '#1a1b1e', border: '1px solid #2a2b2e' }}>
            <CardContent>
              <Box display="flex" alignItems="center" mb={2}>
                <Security sx={{ mr: 1, color: '#ff3838' }} />
                <Typography variant="h6" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                  Total Threats
                </Typography>
              </Box>
              <Typography variant="h3" color="error.main" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                {securityMetrics.totalThreats}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Detected in 24h
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ backgroundColor: '#1a1b1e', border: '1px solid #2a2b2e' }}>
            <CardContent>
              <Box display="flex" alignItems="center" mb={2}>
                <Block sx={{ mr: 1, color: '#00bfff' }} />
                <Typography variant="h6" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                  Blocked
                </Typography>
              </Box>
              <Typography variant="h3" color="primary.main" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                {securityMetrics.blockedThreats}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Successfully blocked
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ backgroundColor: '#1a1b1e', border: '1px solid #2a2b2e' }}>
            <CardContent>
              <Box display="flex" alignItems="center" mb={2}>
                <TrendingUp sx={{ mr: 1, color: '#3ae374' }} />
                <Typography variant="h6" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                  Success Rate
                </Typography>
              </Box>
              <Typography variant="h3" color="success.main" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                {securityMetrics.successRate}%
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Attack prevention
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ backgroundColor: '#1a1b1e', border: '1px solid #2a2b2e' }}>
            <CardContent>
              <Box display="flex" alignItems="center" mb={2}>
                <TrendingDown sx={{ mr: 1, color: '#ff9f1a' }} />
                <Typography variant="h6" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                  Response Time
                </Typography>
              </Box>
              <Typography variant="h3" color="warning.main" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                {securityMetrics.avgResponseTime}ms
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Average response
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Threat Intelligence */}
      <Grid container spacing={3}>
        <Grid item xs={12} lg={8}>
          <Card sx={{ backgroundColor: '#1a1b1e', border: '1px solid #2a2b2e' }}>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
                <Typography variant="h6" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                  Threat Intelligence Database
                </Typography>
                <Button variant="outlined" startIcon={<Refresh />}>
                  Refresh
                </Button>
              </Box>

              <TableContainer component={Paper} sx={{ backgroundColor: 'transparent' }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace' }}>IP Address</TableCell>
                      <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace' }}>Threat Type</TableCell>
                      <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace' }}>Severity</TableCell>
                      <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace' }}>Country</TableCell>
                      <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace' }}>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {threats.slice(0, 10).map((threat, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                          {threat.ip_address}
                        </TableCell>
                        <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                          {threat.threat_type}
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={threat.severity}
                            color={getSeverityColor(threat.severity) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                          {threat.country || 'Unknown'}
                        </TableCell>
                        <TableCell>
                          <Tooltip title="View Details">
                            <IconButton size="small">
                              <Visibility />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Block IP">
                            <IconButton size="small" color="error">
                              <Block />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} lg={4}>
          <Card sx={{ backgroundColor: '#1a1b1e', border: '1px solid #2a2b2e' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                Recent Alerts
              </Typography>

              {alerts.slice(0, 5).map((alert: any, index: number) => (
                <Box key={index} mb={2} p={2} sx={{ border: '1px solid #2a2b2e', borderRadius: 4 }}>
                  <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                    <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                      {alert.timestamp || 'Unknown time'}
                    </Typography>
                    <Chip
                      label={alert.severity}
                      color={getSeverityColor(alert.severity) as any}
                      size="small"
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {alert.message || 'No message'}
                  </Typography>
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Threat Activity Chart */}
      <Grid container spacing={3} sx={{ mt: 2 }}>
        <Grid item xs={12}>
          <Card sx={{ backgroundColor: '#1a1b1e', border: '1px solid #2a2b2e' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ fontFamily: '"JetBrains Mono", monospace' }}>
                Threat Activity (24h)
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#2a2b2e" />
                  <XAxis dataKey="time" stroke="#ffffff" />
                  <YAxis stroke="#ffffff" />
                  <RechartsTooltip />
                  <Legend />
                  <Line type="monotone" dataKey="threats" stroke="#ff3838" strokeWidth={2} />
                  <Line type="monotone" dataKey="blocked" stroke="#00bfff" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default SecurityAnalytics; 