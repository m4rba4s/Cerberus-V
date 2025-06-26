// SPDX-License-Identifier: Apache-2.0
// Network Interface Card Component

import React from 'react';
import { Card, CardContent, Typography, Box, Chip, LinearProgress } from '@mui/material';
import { NetworkCheck, Wifi, Cable, CheckCircle, Error } from '@mui/icons-material';

interface NetworkInterface {
  name: string;
  is_up: boolean;
  rx_packets: number;
  tx_packets: number;
  rx_bytes: number;
  tx_bytes: number;
  mtu?: number;
}

interface NetworkInterfaceCardProps {
  interface: NetworkInterface;
  isActive?: boolean;
}

const NetworkInterfaceCard: React.FC<NetworkInterfaceCardProps> = ({ 
  interface: iface, 
  isActive = false 
}) => {
  const formatBytes = (bytes: number) => {
    const sizes = ['B', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getInterfaceIcon = () => {
    if (iface.name.includes('wl') || iface.name.includes('wifi')) {
      return <Wifi />;
    } else if (iface.name.includes('eth') || iface.name.includes('en')) {
      return <Cable />;
    }
    return <NetworkCheck />;
  };

  return (
    <Card 
      variant={isActive ? 'elevation' : 'outlined'} 
      sx={{ 
        mb: 1,
        border: isActive ? 2 : 1,
        borderColor: isActive ? 'primary.main' : 'divider',
        bgcolor: isActive ? 'action.selected' : 'background.paper'
      }}
    >
      <CardContent sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {getInterfaceIcon()}
            <Typography variant="subtitle2" fontWeight={600}>
              {iface.name}
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Chip
              icon={iface.is_up ? <CheckCircle /> : <Error />}
              label={iface.is_up ? 'UP' : 'DOWN'}
              color={iface.is_up ? 'success' : 'error'}
              size="small"
            />
            {isActive && (
              <Chip
                label="ACTIVE"
                color="primary"
                size="small"
              />
            )}
          </Box>
        </Box>
        
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
  );
};

export default NetworkInterfaceCard; 