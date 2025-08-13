// Centralized types for Cerberus-V Frontend

export interface WebSocketData {
  timestamp?: string;
  mode?: string;
  rules_count?: number;
  status?: string;
  uptime?: number;
  engine_status?: string;
  demo_mode?: boolean;
  interfaces?: Array<{
    name: string;
    status: string;
    speed: number;
  }>;
}

export interface SystemStatus {
  uptime: number;
  engine_status: string;
  demomode: boolean;
  interfaces: Array<{
    name: string;
    status: string;
    speed: number;
  }>;
}

export interface VPPStatus {
  status: string;
  uptime: number;
  version: string;
}

export interface SystemInfo {
  hostname: string;
  os: string;
  kernel: string;
  cpu: string;
  memory: number;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  source: string;
}

export interface SecurityRule {
  id: string;
  action: 'allow' | 'deny' | 'drop';
  protocol: string;
  source: string;
  destination: string;
  port?: number;
  enabled: boolean;
}

export interface SettingsSection {
  id: string;
  title: string;
  description: string;
  icon: string;
  subsections: Array<{
    id: string;
    title: string;
    type: 'boolean' | 'number' | 'string' | 'select';
    value: any;
    options?: Array<{ value: string; label: string }>;
  }>;
}

// Utility types
export type TimeoutHandle = ReturnType<typeof setTimeout>; 