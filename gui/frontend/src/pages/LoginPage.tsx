// SPDX-License-Identifier: Apache-2.0
// Login Page

import React from 'react';
import { Typography, Paper, Box } from '@mui/material';

const LoginPage: React.FC = () => {
  return (
    <Box sx={{ 
      display: 'flex', 
      justifyContent: 'center', 
      alignItems: 'center', 
      minHeight: '100vh',
      backgroundColor: 'background.default'
    }}>
      <Paper sx={{ p: 4, maxWidth: 400, width: '100%' }}>
        <Typography variant="h4" align="center" gutterBottom>
          VPP eBPF Firewall
        </Typography>
        <Typography variant="body1" align="center">
          Auto-logged in as Admin
        </Typography>
      </Paper>
    </Box>
  );
};

export default LoginPage; 