// SPDX-License-Identifier: Apache-2.0
// Status Indicator Component

import React from 'react';
import { Box, Typography, Chip } from '@mui/material';
import { CheckCircle, Error, Warning, HourglassEmpty } from '@mui/icons-material';

interface StatusIndicatorProps {
  status: 'Connected' | 'Disconnected' | 'Connecting' | 'Error';
  label?: string;
  sx?: any;
}

const StatusIndicator: React.FC<StatusIndicatorProps> = ({ 
  status, 
  label = 'Status',
  sx = {}
}) => {
  const getStatusConfig = () => {
    switch (status) {
      case 'Connected':
        return {
          icon: <CheckCircle />,
          color: 'success' as const,
          text: 'Connected'
        };
      case 'Connecting':
        return {
          icon: <HourglassEmpty />,
          color: 'warning' as const,
          text: 'Connecting'
        };
      case 'Error':
        return {
          icon: <Error />,
          color: 'error' as const,
          text: 'Error'
        };
      default:
        return {
          icon: <Warning />,
          color: 'default' as const,
          text: 'Disconnected'
        };
    }
  };

  const config = getStatusConfig();

  return (
    <Box sx={sx}>
      <Chip
        icon={config.icon}
        label={`${label}: ${config.text}`}
        color={config.color}
        variant="outlined"
        size="small"
      />
    </Box>
  );
};

export default StatusIndicator; 