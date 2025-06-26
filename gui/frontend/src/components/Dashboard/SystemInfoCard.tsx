// SPDX-License-Identifier: Apache-2.0
// System Information Card Component

import React from 'react';
import { Card, CardContent, Typography, Box, LinearProgress } from '@mui/material';
import { Computer, Memory, Speed } from '@mui/icons-material';

interface SystemInfo {
  hostname: string;
  kernel_version: string;
  cpu_cores: number;
  total_memory: number;
  uptime: string;
  load_average: number[];
}

interface SystemInfoCardProps {
  systemInfo: SystemInfo | null;
  stats?: any;
}

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const SystemInfoCard: React.FC<SystemInfoCardProps> = ({ systemInfo, stats }) => {
  if (!systemInfo) {
    return (
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <Computer color="primary" />
            <Typography variant="h6">System Information</Typography>
          </Box>
          <Typography variant="body2" color="text.secondary">
            Loading system information...
          </Typography>
        </CardContent>
      </Card>
    );
  }

  const avgLoad = systemInfo.load_average[0] || 0;
  const loadPercentage = Math.min((avgLoad / systemInfo.cpu_cores) * 100, 100);
  
  return (
    <Card>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <Computer color="primary" />
          <Typography variant="h6">System Information</Typography>
        </Box>
        
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <Box>
            <Typography variant="body2" color="text.secondary">
              Hostname
            </Typography>
            <Typography variant="body1" fontWeight={500}>
              {systemInfo.hostname}
            </Typography>
          </Box>
          
          <Box>
            <Typography variant="body2" color="text.secondary">
              Kernel
            </Typography>
            <Typography variant="body1" fontWeight={500}>
              {systemInfo.kernel_version}
            </Typography>
          </Box>
          
          <Box>
            <Typography variant="body2" color="text.secondary">
              CPU Cores
            </Typography>
            <Typography variant="body1" fontWeight={500}>
              {systemInfo.cpu_cores}
            </Typography>
          </Box>
          
          <Box>
            <Typography variant="body2" color="text.secondary">
              Memory
            </Typography>
            <Typography variant="body1" fontWeight={500}>
              {formatBytes(systemInfo.total_memory)}
            </Typography>
          </Box>
          
          <Box>
            <Typography variant="body2" color="text.secondary">
              Load Average
            </Typography>
            <Typography variant="body1" fontWeight={500}>
              {avgLoad.toFixed(2)}
            </Typography>
            <LinearProgress 
              variant="determinate" 
              value={loadPercentage} 
              color={loadPercentage > 80 ? 'error' : loadPercentage > 60 ? 'warning' : 'primary'}
              sx={{ mt: 1 }}
            />
          </Box>
          
          <Box>
            <Typography variant="body2" color="text.secondary">
              Uptime
            </Typography>
            <Typography variant="body1" fontWeight={500}>
              {systemInfo.uptime}
            </Typography>
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

export default SystemInfoCard; 