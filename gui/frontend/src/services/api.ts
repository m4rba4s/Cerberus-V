// SPDX-License-Identifier: Apache-2.0
// API Service for VPP eBPF Firewall Management

import axios, { AxiosInstance, AxiosResponse } from 'axios';

// API Configuration
const API_BASE_URL = (window as any).REACT_APP_API_URL || 'http://localhost:8081';

// Create axios instance
const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor for authentication
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor for error handling
apiClient.interceptors.response.use(
  (response: AxiosResponse) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('auth_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Type definitions
export interface FirewallConfig {
  interface: string;
  xdp_program: string;
  queue_id: number;
  verbose: boolean;
  auto_start: boolean;
}

export interface FirewallStats {
  packets_passed: number;
  packets_dropped: number;
  packets_redirected: number;
  packets_error: number;
  bytes_processed: number;
  pps_current: number;
  cpu_usage: number;
  memory_usage: number;
}

export interface InterfaceInfo {
  name: string;
  index: number;
  mtu: number;
  speed?: number;
  is_up: boolean;
  has_xdp: boolean;
  rx_packets: number;
  tx_packets: number;
  rx_bytes: number;
  tx_bytes: number;
}

export interface SystemInfo {
  hostname: string;
  kernel_version: string;
  cpu_cores: number;
  total_memory: number;
  uptime: string;
  load_average: number[];
}

export interface FirewallStatus {
  is_running: boolean;
  config: FirewallConfig;
  uptime: string;
  process_id: number | null;
}

// API Functions
export const firewallAPI = {
  // Status and Control
  getStatus: async (): Promise<FirewallStatus> => {
    const response = await apiClient.get('/api/status');
    return response.data;
  },

  start: async (config: FirewallConfig): Promise<{ message: string; config: FirewallConfig }> => {
    const response = await apiClient.post('/api/start', config);
    return response.data;
  },

  stop: async (): Promise<{ message: string }> => {
    const response = await apiClient.post('/api/stop');
    return response.data;
  },

  restart: async (): Promise<{ message: string }> => {
    const response = await apiClient.post('/api/restart');
    return response.data;
  },

  // Statistics
  getStats: async (): Promise<FirewallStats> => {
    const response = await apiClient.get('/api/stats');
    return response.data;
  },

  // Network Interfaces
  getInterfaces: async (): Promise<InterfaceInfo[]> => {
    const response = await apiClient.get('/api/interfaces');
    return response.data;
  },

  // System Information
  getSystemInfo: async (): Promise<SystemInfo> => {
    const response = await apiClient.get('/api/system');
    return response.data;
  },

  // Active Interface
  getActiveInterface: async (): Promise<{ active_interface: string }> => {
    const response = await apiClient.get('/api/active-interface');
    return response.data;
  },

  // Detailed Interfaces
  getInterfacesDetailed: async (): Promise<{
    interfaces: Array<{
      name: string;
      type: string;
      is_up: boolean;
      mtu: number;
      speed: number;
      ip_addresses: string[];
      rx_packets: number;
      tx_packets: number;
      rx_bytes: number;
      tx_bytes: number;
      total_bytes: number;
      is_physical: boolean;
      has_ip: boolean;
    }>;
    recommended: string;
    total_count: number;
  }> => {
    const response = await apiClient.get('/api/interfaces-detailed');
    return response.data;
  },
};

// Authentication API
export const authAPI = {
  login: async (credentials: { username: string; password: string }): Promise<{ access_token: string; token_type: string }> => {
    const response = await apiClient.post('/auth/login', credentials);
    return response.data;
  },

  logout: async (): Promise<{ message: string }> => {
    const response = await apiClient.post('/auth/logout');
    return response.data;
  },

  getCurrentUser: async (): Promise<{ username: string; permissions: string[] }> => {
    const response = await apiClient.get('/auth/me');
    return response.data;
  },
};

// Configuration API
export const configAPI = {
  getConfig: async (): Promise<FirewallConfig> => {
    const response = await apiClient.get('/api/config');
    return response.data;
  },

  updateConfig: async (config: Partial<FirewallConfig>): Promise<FirewallConfig> => {
    const response = await apiClient.put('/api/config', config);
    return response.data;
  },

  resetConfig: async (): Promise<FirewallConfig> => {
    const response = await apiClient.post('/api/config/reset');
    return response.data;
  },
};

// Monitoring API
export const monitoringAPI = {
  getMetrics: async (timeRange: string = '1h'): Promise<any[]> => {
    const response = await apiClient.get(`/api/monitoring/metrics?range=${timeRange}`);
    return response.data;
  },

  getAlerts: async (): Promise<any[]> => {
    const response = await apiClient.get('/api/monitoring/alerts');
    return response.data;
  },

  acknowledgeAlert: async (alertId: string): Promise<{ message: string }> => {
    const response = await apiClient.post(`/api/monitoring/alerts/${alertId}/acknowledge`);
    return response.data;
  },
};

export default apiClient; 