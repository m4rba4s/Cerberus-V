import React, { useState, useEffect } from 'react';
import { Box, Card, CardContent, Typography, Grid, Tabs, Tab, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Chip, Button, Alert, CircularProgress, IconButton, Dialog, DialogTitle, DialogContent, DialogActions, Menu, MenuItem, LinearProgress } from '@mui/material';
import Forensics from './ForensicsTab';
import { Security, NetworkCheck, Settings, Public, Search, Analytics as AnalyticsIcon, MoreVert, PlayArrow, Stop, Refresh, Shield, BugReport } from '@mui/icons-material';

interface LiveThreat {
  id: string;
  timestamp: string;
  sourceIp: string;
  targetIp: string;
  country: string;
  attackType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  blocked: boolean;
  confidence: number;
  protocol: string;
  port: number;
  status: 'active' | 'blocked' | 'investigating' | 'resolved';
  description?: string;
  mitreId?: string;
  mitreTactic?: string;
  mitreTechnique?: string;
}

interface NetworkFlow {
  id: string;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  port: number;
  bytesIn: number;
  bytesOut: number;
  duration: number;
  suspicious: boolean;
  country: string;
  service: string;
  encrypted: boolean;
  packets: number;
  flags: string[];
}

interface ServiceMetrics {
  service: string;
  status: 'running' | 'stopped' | 'warning' | 'error';
  connections: number;
  bandwidth: number;
  cpu: number;
  memory: number;
  uptime: string;
  threats: number;
  blocked: number;
  version?: string;
  pid?: number;
}

const Analytics: React.FC = () => {
  const [currentTab, setCurrentTab] = useState(0);
  const [liveThreats, setLiveThreats] = useState<LiveThreat[]>([]);
  const [networkFlows, setNetworkFlows] = useState<NetworkFlow[]>([]);
  const [serviceMetrics, setServiceMetrics] = useState<ServiceMetrics[]>([]);
  const [geoSummary, setGeoSummary] = useState<{private:number; public:number}>({private:0, public:0});
  const [topPorts, setTopPorts] = useState<Array<{port:number; count:number; service:string}>>([]);
  const [topSources, setTopSources] = useState<Array<{value:string; count:number}>>([]);
  const [topDestinations, setTopDestinations] = useState<Array<{value:string; count:number}>>([]);
  const [blockedCountries, setBlockedCountries] = useState<string[]>([]);
  const [countries, setCountries] = useState<Array<{code:string; count:number}>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<LiveThreat | null>(null);
  const [mitigationDialog, setMitigationDialog] = useState(false);
  const [actionMenuAnchor, setActionMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedFlow, setSelectedFlow] = useState<NetworkFlow | null>(null);
  const [actionInProgress, setActionInProgress] = useState(false);
  const [lastActionResult, setLastActionResult] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    const load = () => fetchAnalyticsData(controller.signal);
    load();
    const interval = setInterval(load, 8000);
    return () => { controller.abort(); clearInterval(interval); };
  }, []);

  const fetchAnalyticsData = async (signal?: AbortSignal) => {
    try {
      const [threatsRes, flowsRes, servicesRes, geoRes] = await Promise.all([
        fetch('/api/analytics/live-threats', { signal }),
        fetch('/api/analytics/network-flows', { signal }),
        fetch('/api/analytics/service-metrics', { signal }),
        fetch('/api/analytics/geo', { signal })
      ]);

      // Handle each response individually
      if (threatsRes.ok) {
        const threatsData = await threatsRes.json();
        setLiveThreats(threatsData.threats || []);
      }
      
      if (flowsRes.ok) {
        const flowsData = await flowsRes.json();
        setNetworkFlows(flowsData.flows || []);
      }
      
      if (servicesRes.ok) {
        const servicesData = await servicesRes.json();
        setServiceMetrics(servicesData.services || []);
      }

      if (geoRes.ok) {
        const geo = await geoRes.json();
        setGeoSummary(geo.geo || {private:0, public:0});
        setTopPorts(geo.topPorts || []);
        setTopSources(geo.topSources || []);
        setTopDestinations(geo.topDestinations || []);
        setBlockedCountries(geo.blockedCountries || []);
        setCountries(geo.countries || []);
      }

      // Only set error if ALL requests failed
      if (!threatsRes.ok && !flowsRes.ok && !servicesRes.ok && !geoRes.ok) {
        setError('Failed to fetch analytics data');
      } else {
        setError(null);
      }
    } catch (err) {
      if ((err as any)?.name === 'AbortError') return;
      setError('Failed to fetch analytics data');
      console.error('Analytics fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleThreatMitigation = async (threat: LiveThreat, action: string) => {
    setActionInProgress(true);
    setLastActionResult(null);
    
    try {
      const response = await fetch('/api/flow/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          flowId: threat.id,
          action: action,
          sourceIp: threat.sourceIp,
          destinationIp: threat.targetIp,
          port: threat.port,
          protocol: threat.protocol.toLowerCase(),
          country: threat.country,
          reason: `Threat mitigation: ${threat.attackType}`
        })
      });

      if (response.ok) {
        const result = await response.json();
        console.log(`Mitigation ${action} applied to threat ${threat.id}:`, result);
        
        setLastActionResult(`✅ ${result.message || 'Action applied successfully'}`);
        
        // Auto-close dialog after 2 seconds
        setTimeout(() => {
          setMitigationDialog(false);
          setSelectedThreat(null);
          setLastActionResult(null);
        }, 2000);
        
        // Refresh data
        fetchAnalyticsData();
      } else {
        const error = await response.json();
        console.error('Mitigation failed:', error);
        setLastActionResult(`❌ Error: ${error.detail || 'Action failed'}`);
      }
    } catch (err) {
      console.error('Threat mitigation error:', err);
      setLastActionResult('❌ Network error occurred');
    } finally {
      setActionInProgress(false);
    }
  };

  const handleFlowAction = async (flow: NetworkFlow, action: string) => {
    try {
      const response = await fetch('/api/flow/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          flowId: flow.id,
          action: action,
          sourceIp: flow.sourceIp,
          destinationIp: flow.destinationIp,
          port: flow.port,
          protocol: flow.protocol.toLowerCase(),
          country: flow.country
        })
      });

      if (response.ok) {
        const result = await response.json();
        console.log(`Action ${action} applied to flow ${flow.id}:`, result);
        
        // Show success message
        alert(`✅ ${result.message || 'Action applied successfully'}`);
        
        // Refresh data and close menu
        fetchAnalyticsData();
        setActionMenuAnchor(null);
        setSelectedFlow(null);
      } else {
        const error = await response.json();
        console.error('Flow action failed:', error);
        alert(`❌ Error: ${error.detail || 'Action failed'}`);
      }
    } catch (err) {
      console.error('Flow action error:', err);
      alert('❌ Network error occurred');
    }
  };

  const handleServiceAction = async (serviceName: string, action: string) => {
    try {
      const response = await fetch(`/api/system/service/${serviceName}/${action}`, {
        method: 'POST'
      });
      if (response.ok) {
        console.log(`Service ${serviceName} ${action} executed`);
        fetchAnalyticsData();
      }
    } catch (err) {
      console.error('Service action error:', err);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'success';
      case 'stopped': return 'error';
      case 'warning': return 'warning';
      case 'error': return 'error';
      default: return 'default';
    }
  };

  const getMitigationActions = () => [
    { id: 'block_ip', label: '🚫 Block IP Address', description: 'Block source IP immediately', severity: 'high' },
    { id: 'block_country', label: '🌍 Block Country', description: 'Block entire country IP ranges', severity: 'high' },
    { id: 'rate_limit', label: '⏳ Rate Limit', description: 'Apply traffic throttling', severity: 'medium' },
    { id: 'quarantine', label: '🔒 Quarantine', description: 'Isolate connection for analysis', severity: 'medium' },
    { id: 'investigate', label: '🔍 Investigate', description: 'Mark for manual investigation', severity: 'low' },
    { id: 'redirect_honeypot', label: '🍯 Redirect to Honeypot', description: 'Redirect to honeypot system', severity: 'medium' },
    { id: 'whitelist', label: '✅ Whitelist', description: 'Add to trusted sources', severity: 'low' }
  ];

  if (loading) {
    return (
      <Box sx={{ p: 3, display: 'flex', justifyContent: 'center', alignItems: 'center', height: '400px' }}>
        <CircularProgress size={60} />
        <Typography sx={{ ml: 2 }}>Loading professional analytics...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <AnalyticsIcon color="primary" />
        🔬 Professional Security Operations Center
        <Chip label="SOC Level 3" color="success" />
        <Chip label={`${liveThreats.length} Threats`} color="error" />
        <Chip label={`${networkFlows.length} Flows`} color="info" />
      </Typography>

      {error && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          {error} - Using demo data for display
        </Alert>
      )}

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={currentTab} onChange={(_, newValue) => setCurrentTab(newValue)} variant="scrollable">
          <Tab label="🚨 Live Threats" icon={<Security />} />
          <Tab label="🌐 Network Flows" icon={<NetworkCheck />} />
          <Tab label="⚙️ Service Control" icon={<Settings />} />
          <Tab label="🗺️ Geo Analytics" icon={<Public />} />
          <Tab label="🔍 Forensics" icon={<Search />} />
          <Tab label="🛡️ MITRE ATT&CK" icon={<Shield />} />
          <Tab label="📈 Threat Hunting" icon={<BugReport />} />
        </Tabs>
      </Box>

      {/* Live Threats Tab */}
      {currentTab === 0 && (
        <Grid container spacing={3}>
          {/* Threat Statistics Cards */}
          <Grid item xs={12}>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={3}>
                <Card sx={{ bgcolor: 'error.light', color: 'white' }}>
                  <CardContent>
                    <Typography variant="h4">{liveThreats.filter(t => t.severity === 'critical').length}</Typography>
                    <Typography>Critical Threats</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={3}>
                <Card sx={{ bgcolor: 'warning.light', color: 'white' }}>
                  <CardContent>
                    <Typography variant="h4">{liveThreats.filter(t => t.severity === 'high').length}</Typography>
                    <Typography>High Threats</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={3}>
                <Card sx={{ bgcolor: 'info.light', color: 'white' }}>
                  <CardContent>
                    <Typography variant="h4">{liveThreats.filter(t => t.blocked).length}</Typography>
                    <Typography>Blocked</Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={3}>
                <Card sx={{ bgcolor: 'success.light', color: 'white' }}>
                  <CardContent>
                    <Typography variant="h4">{liveThreats.filter(t => t.status === 'resolved').length}</Typography>
                    <Typography>Resolved</Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Grid>

          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                🚨 Real-time Threat Detection & Mitigation
                <Chip label={`${liveThreats.length} Active`} color="error" sx={{ ml: 2 }} />
              </Typography>

              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Timestamp</TableCell>
                      <TableCell>Source IP</TableCell>
                      <TableCell>Target</TableCell>
                      <TableCell>Attack Type</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>MITRE</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {liveThreats.slice(0, 15).map((threat) => (
                      <TableRow key={threat.id} hover>
                        <TableCell>{new Date(threat.timestamp).toLocaleTimeString()}</TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {threat.sourceIp}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            📍 {threat.country}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {threat.targetIp}:{threat.port}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {threat.protocol}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={threat.attackType} size="small" />
                          <Typography variant="caption" display="block">
                            Confidence: {threat.confidence}%
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={threat.severity} 
                            color={getSeverityColor(threat.severity) as any}
                            size="small" 
                          />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={threat.status} 
                            color={threat.blocked ? 'success' : 'error'}
                            size="small" 
                          />
                        </TableCell>
                        <TableCell>
                          {threat.mitreId && (
                            <Box sx={{ display:'flex', gap: 0.5, alignItems:'center', flexWrap:'wrap' }}>
                              <Chip label={threat.mitreId} size="small" variant="outlined" color="secondary" />
                              {threat.mitreTactic && <Chip label={threat.mitreTactic} size="small" />}
                              {threat.mitreTechnique && <Chip label={threat.mitreTechnique} size="small" />}
                            </Box>
                          )}
                        </TableCell>
                        <TableCell>
                          <Button 
                            size="small" 
                            variant="outlined" 
                            color="error"
                            disabled={threat.blocked}
                            onClick={() => {
                              setSelectedThreat(threat);
                              setMitigationDialog(true);
                            }}
                          >
                            {threat.blocked ? 'Blocked' : 'Mitigate'}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Network Flows Tab */}
      {currentTab === 1 && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                🌐 Network Flow Analysis & Control
                <Chip label={`${networkFlows.length} Active Flows`} color="info" sx={{ ml: 2 }} />
                <Chip label={`${networkFlows.filter(f => f.suspicious).length} Suspicious`} color="warning" sx={{ ml: 1 }} />
              </Typography>

              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Source</TableCell>
                      <TableCell>Destination</TableCell>
                      <TableCell>Protocol</TableCell>
                      <TableCell>Traffic</TableCell>
                      <TableCell>Duration</TableCell>
                      <TableCell>Flags</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {networkFlows.slice(0, 15).map((flow) => (
                      <TableRow key={flow.id} hover>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {flow.sourceIp}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            📍 {flow.country}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {flow.destinationIp}:{flow.port}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {flow.service}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={flow.protocol} size="small" />
                          {flow.encrypted && <Chip label="🔒" size="small" sx={{ ml: 0.5 }} />}
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            ↓{(flow.bytesIn / 1024).toFixed(1)}KB ↑{(flow.bytesOut / 1024).toFixed(1)}KB
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {flow.packets} packets
                          </Typography>
                        </TableCell>
                        <TableCell>{flow.duration}s</TableCell>
                        <TableCell>
                          {flow.flags.map((flag, idx) => (
                            <Chip key={idx} label={flag} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                          ))}
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={flow.suspicious ? 'Suspicious' : 'Normal'} 
                            color={flow.suspicious ? 'warning' : 'success'}
                            size="small" 
                          />
                        </TableCell>
                        <TableCell>
                          <IconButton
                            size="small"
                            onClick={(e) => {
                              setSelectedFlow(flow);
                              setActionMenuAnchor(e.currentTarget);
                            }}
                          >
                            <MoreVert />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* Service Control Tab */}
      {currentTab === 2 && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Typography variant="h6" gutterBottom>
              ⚙️ System Service Management & Monitoring
            </Typography>
          </Grid>
          
          {serviceMetrics.map((service) => (
            <Grid item xs={12} md={6} lg={4} key={service.service}>
              <Card sx={{ height: '100%' }}>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6">{service.service}</Typography>
                    <Chip 
                      label={service.status} 
                      color={getStatusColor(service.status) as any}
                    />
                  </Box>
                  
                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="textSecondary">
                        Connections: {service.connections}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="textSecondary">
                        Uptime: {service.uptime}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="textSecondary">
                        Threats: {service.threats}
                      </Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="body2" color="textSecondary">
                        Blocked: {service.blocked}
                      </Typography>
                    </Grid>
                  </Grid>

                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" gutterBottom>
                      CPU: {service.cpu}%
                    </Typography>
                    <LinearProgress 
                      variant="determinate" 
                      value={service.cpu} 
                      color={service.cpu > 80 ? 'error' : service.cpu > 60 ? 'warning' : 'success'}
                    />
                  </Box>

                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" gutterBottom>
                      Memory: {service.memory}%
                    </Typography>
                    <LinearProgress 
                      variant="determinate" 
                      value={service.memory} 
                      color={service.memory > 80 ? 'error' : service.memory > 60 ? 'warning' : 'success'}
                    />
                  </Box>
                  
                  <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                    <Button 
                      size="small" 
                      variant="outlined" 
                      color="success"
                      startIcon={<PlayArrow />}
                      onClick={() => handleServiceAction(service.service, 'start')}
                      disabled={service.status === 'running'}
                    >
                      Start
                    </Button>
                    <Button 
                      size="small" 
                      variant="outlined" 
                      color="error"
                      startIcon={<Stop />}
                      onClick={() => handleServiceAction(service.service, 'stop')}
                      disabled={service.status === 'stopped'}
                    >
                      Stop
                    </Button>
                    <Button 
                      size="small" 
                      variant="outlined" 
                      color="warning"
                      startIcon={<Refresh />}
                      onClick={() => handleServiceAction(service.service, 'restart')}
                    >
                      Restart
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Other tabs with professional content placeholders */}
      {currentTab === 3 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>🗺️ Geographic Threat Intelligence</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1">Traffic by Origin</Typography>
                  <Box sx={{ display:'flex', gap:2, mt:1 }}>
                    <Chip label={`Private ${geoSummary.private}`} color="info" />
                    <Chip label={`Public ${geoSummary.public}`} color="primary" />
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1">Top Ports</Typography>
                  {topPorts.slice(0,8).map(p => (
                    <Box key={p.port} sx={{ display:'flex', justifyContent:'space-between' }}>
                      <Typography variant="body2">{p.port} ({p.service})</Typography>
                      <Typography variant="body2">{p.count}</Typography>
                    </Box>
                  ))}
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1">Top Sources</Typography>
                  {topSources.slice(0,8).map(s => (
                    <Box key={s.value} sx={{ display:'flex', justifyContent:'space-between' }}>
                      <Typography variant="body2">{s.value}</Typography>
                      <Typography variant="body2">{s.count}</Typography>
                    </Box>
                  ))}
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1">Top Countries</Typography>
                  {countries.slice(0,12).map(c => (
                    <Box key={c.code} sx={{ display:'flex', justifyContent:'space-between' }}>
                      <Typography variant="body2">{c.code}</Typography>
                      <Typography variant="body2">{c.count}</Typography>
                    </Box>
                  ))}
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>Block Country</Typography>
                  <Box sx={{ display:'flex', gap:1, flexWrap:'wrap' }}>
                    {countries.slice(0,20).map(c => (
                      <Button key={c.code} size="small" variant="outlined" onClick={async ()=>{
                        try{await fetch('/api/geo/block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({country:c.code})});
                          fetchAnalyticsData();}catch(e){/* noop */}
                      }}>{c.code}</Button>
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>Blocked Countries</Typography>
                  <Box sx={{ display:'flex', gap:1, flexWrap:'wrap' }}>
                    {blockedCountries.map(c => (<Chip key={c} label={c} />))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </Paper>
      )}

      {currentTab === 4 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>🔍 Digital Forensics & Evidence Collection</Typography>
          <Forensics />
        </Paper>
      )}

      {currentTab === 5 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>🛡️ MITRE ATT&CK Overview</Typography>
          {(() => {
            const summaryMap: Record<string, { id: string; tactic: string; technique: string; count: number }> = {};
            for (const t of liveThreats) {
              if (!t.mitreId) continue;
              if (!summaryMap[t.mitreId]) {
                summaryMap[t.mitreId] = {
                  id: t.mitreId,
                  tactic: t.mitreTactic || '',
                  technique: t.mitreTechnique || '',
                  count: 0,
                };
              }
              summaryMap[t.mitreId].count += 1;
            }
            const rows = Object.values(summaryMap).sort((a,b)=> b.count - a.count);
            if (rows.length === 0) {
              return (
                <Alert severity="warning">Нет данных MITRE в текущих угрозах. Зайдите на вкладку "Live Threats" или подождите новые события.</Alert>
              );
            }
            return (
              <TableContainer sx={{ mt: 2 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Technique ID</TableCell>
                      <TableCell>Technique</TableCell>
                      <TableCell>Tactic</TableCell>
                      <TableCell align="right">Count</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rows.map(r => (
                      <TableRow key={r.id} hover>
                        <TableCell><Chip label={r.id} size="small" color="secondary" variant="outlined" /></TableCell>
                        <TableCell>{r.technique || '—'}</TableCell>
                        <TableCell>{r.tactic || '—'}</TableCell>
                        <TableCell align="right">{r.count}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            );
          })()}
        </Paper>
      )}

      {currentTab === 6 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>📈 Advanced Threat Hunting</Typography>
          <Alert severity="info">
            Proactive threat hunting, behavioral analysis, anomaly detection, and threat hypothesis testing.
          </Alert>
        </Paper>
      )}

      {/* Mitigation Dialog */}
      <Dialog open={mitigationDialog} onClose={() => setMitigationDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          🛡️ Threat Mitigation Options
          {selectedThreat && (
            <Typography variant="subtitle2" color="text.secondary">
              Target: {selectedThreat.sourceIp} → {selectedThreat.targetIp} | {selectedThreat.attackType}
            </Typography>
          )}
        </DialogTitle>
        <DialogContent>
          {/* Action Result Display */}
          {lastActionResult && (
            <Alert 
              severity={lastActionResult.includes('✅') ? 'success' : 'error'} 
              sx={{ mb: 3 }}
              onClose={() => setLastActionResult(null)}
            >
              {lastActionResult}
            </Alert>
          )}
          
          {/* Loading Indicator */}
          {actionInProgress && (
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
              <CircularProgress size={24} sx={{ mr: 2 }} />
              <Typography>Processing mitigation action...</Typography>
            </Box>
          )}
          
          <Grid container spacing={2}>
            {getMitigationActions().map((action) => (
              <Grid item xs={12} sm={6} key={action.id}>
                <Card 
                  sx={{ 
                    cursor: actionInProgress ? 'not-allowed' : 'pointer',
                    transition: 'all 0.3s ease',
                    opacity: actionInProgress ? 0.6 : 1,
                    '&:hover': actionInProgress ? {} : { transform: 'scale(1.02)', boxShadow: 3 }
                  }}
                  onClick={() => !actionInProgress && selectedThreat && handleThreatMitigation(selectedThreat, action.id)}
                >
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      {action.label}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {action.description}
                    </Typography>
                    <Chip 
                      label={action.severity} 
                      size="small" 
                      color={action.severity === 'high' ? 'error' : action.severity === 'medium' ? 'warning' : 'success'}
                      sx={{ mt: 1 }}
                    />
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button 
            onClick={() => {
              setMitigationDialog(false);
              setLastActionResult(null);
              setSelectedThreat(null);
            }}
            disabled={actionInProgress}
          >
            {actionInProgress ? 'Processing...' : 'Cancel'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Flow Action Menu */}
      <Menu
        anchorEl={actionMenuAnchor}
        open={Boolean(actionMenuAnchor)}
        onClose={() => setActionMenuAnchor(null)}
      >
        <MenuItem onClick={() => selectedFlow && handleFlowAction(selectedFlow, 'block_ip')}>
          🚫 Block IP
        </MenuItem>
        <MenuItem onClick={() => selectedFlow && handleFlowAction(selectedFlow, 'rate_limit')}>
          ⏳ Rate Limit
        </MenuItem>
        <MenuItem onClick={() => selectedFlow && handleFlowAction(selectedFlow, 'quarantine')}>
          🔒 Quarantine
        </MenuItem>
        <MenuItem onClick={() => selectedFlow && handleFlowAction(selectedFlow, 'investigate')}>
          🔍 Investigate
        </MenuItem>
        <MenuItem onClick={() => selectedFlow && handleFlowAction(selectedFlow, 'whitelist')}>
          ✅ Whitelist
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default Analytics; 