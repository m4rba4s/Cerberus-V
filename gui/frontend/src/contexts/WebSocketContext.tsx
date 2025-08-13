// SPDX-License-Identifier: Apache-2.0
// WebSocket Context for real-time communication

import React, { createContext, useContext, useEffect, useRef, useState, useCallback, memo } from 'react';

interface SystemInfo {
  hostname: string;
  kernel_version: string;
  cpu_cores: number;
  total_memory: number;
  uptime: string;
  load_average: number[];
}

interface InterfaceInfo {
  name: string;
  index: number;
  mtu: number;
  speed?: number;
  is_up: boolean;
  has_xdp?: boolean;
  rx_packets: number;
  tx_packets: number;
  rx_bytes: number;
  tx_bytes: number;
}

interface FirewallStats {
  packets_passed: number;
  packets_dropped: number;
  packets_redirected: number;
  packets_error: number;
  bytes_processed: number;
  pps_current: number;
  cpu_usage: number;
  memory_usage: number;
}

interface DualProtectionStats {
  enabled: boolean;
  protection_mode: string;
  vpp_stats?: {
    status: string;
    packets_processed: number;
    packets_dropped: number;
    throughput_mbps: number;
  };
  ebpf_stats?: {
    status: string;
    packets_processed: number;
    packets_dropped: number;
    cpu_usage: number;
  };
}

// Realtime, flattened payloads used by UI (tolerant to backend changes)
interface FirewallRealtime {
  engine_status?: 'running' | 'inactive' | 'simulation' | 'error';
  protection_mode?: string;
  dual_protection_active?: boolean;
  packets_processed?: number;
  packets_blocked?: number;
  ebpf_programs?: number;
  vpp_interfaces?: number;
  interface?: string;
}

interface SystemRealtime {
  uptime?: number; // seconds
  cpu_usage?: number; // percent
  memory_used?: number; // bytes
  memory_total?: number; // bytes
}

interface WebSocketData {
  type?: string;
  timestamp?: string;
  data?: {
    system_info?: SystemInfo;
    interfaces?: InterfaceInfo[];
    firewall_stats?: FirewallStats;
    dual_protection?: DualProtectionStats;
    is_running?: boolean;
    uptime?: string;
    firewall_mode?: string;
    rules_count?: number;
    filters_count?: number;
  };
  message_type?: string;
  // Support direct properties for compatibility
  system_info?: SystemInfo;
  interfaces?: InterfaceInfo[];
  firewall_stats?: FirewallStats;
  dual_protection?: DualProtectionStats;
  is_running?: boolean;
  uptime?: string;
  // Flattened, enterprise-friendly fields used by dashboard
  firewall?: FirewallRealtime;
  system?: SystemRealtime;
}

interface WebSocketContextType {
  data: WebSocketData | null;
  connectionState: 'connecting' | 'connected' | 'disconnected' | 'error' | 'reconnecting';
  isConnected: boolean;
  reconnectCount: number;
  lastError: string | null;
  forceReconnect: () => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

// Простой WebSocket без Singleton
class SimpleWebSocket {
  private ws: WebSocket | null = null;
  private url: string = 'ws://localhost:8000/ws';
  private listeners: Set<(data: WebSocketData) => void> = new Set();
  private stateListeners: Set<(state: string) => void> = new Set();
  private reconnectTimer: number | null = null;
  private isDestroyed = false;
  private currentState: string = 'disconnected';
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000; // Start with 1 second

  public connect(): void {
    if (this.isDestroyed || this.ws?.readyState === WebSocket.CONNECTING || this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    this.updateState('connecting');
    console.log('🔌 Подключаемся к WebSocket...');

    try {
      this.ws = new WebSocket(this.url);
      this.ws.onopen = () => { this.updateState('connected'); };
      
      this.ws.onmessage = (event: MessageEvent) => {
        try {
          const data: WebSocketData = JSON.parse(event.data);
          this.listeners.forEach(listener => {
            try {
              listener(data);
            } catch (error) {
              console.error('❌ Ошибка в listener:', error);
            }
          });
        } catch (error) {
          console.error('❌ Ошибка парсинга JSON:', error);
        }
      };
      
      this.ws.onclose = (_event: CloseEvent) => {
        this.updateState('disconnected');
        // Auto-reconnect logic
        if (!this.isDestroyed && this.reconnectAttempts < this.maxReconnectAttempts) {
          if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
          }
          
          this.reconnectAttempts++;
          const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), 30000);
          
          this.reconnectTimer = window.setTimeout(() => {
            this.connect();
          }, delay);
        } else if (this.reconnectAttempts >= this.maxReconnectAttempts) {
          this.updateState('error');
        }
      };
      this.ws.onerror = (_event: Event) => { this.updateState('error'); };

    } catch (error) {
      console.error('❌ Ошибка создания WebSocket:', error);
      this.updateState('error');
    }
  }

  private updateState(state: string): void {
    this.currentState = state;
    this.stateListeners.forEach(listener => {
      try {
        listener(state);
      } catch (error) {
        console.error('🚨 Error in state listener:', error);
      }
    });
  }

  public addListener(listener: (data: WebSocketData) => void): void {
    this.listeners.add(listener);
  }

  public removeListener(listener: (data: WebSocketData) => void): void {
    this.listeners.delete(listener);
  }

  public addStateListener(listener: (state: string) => void): void {
    this.stateListeners.add(listener);
  }

  public removeStateListener(listener: (state: string) => void): void {
    this.stateListeners.delete(listener);
  }

  public forceReconnect(): void { this.ws?.close(); setTimeout(() => this.connect(), 200); }

  public getState(): string {
    return this.currentState;
  }

  public disconnect(): void {
    console.log('🔌 WebSocket отключается');
    this.isDestroyed = true;
    this.ws?.close(1000, 'Client disconnect');
    this.ws = null;
    this.updateState('disconnected');
  }
}

const WSProviderInner: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [data, setData] = useState<WebSocketData | null>(null);
  const [connectionState, setConnectionState] = useState<'connecting' | 'connected' | 'disconnected' | 'error' | 'reconnecting'>('disconnected');
  const [lastError, setLastError] = useState<string | null>(null);
  
  const wsRef = useRef<SimpleWebSocket | null>(null);
  
  // Stable callback references
  const handleData = useCallback((newData: WebSocketData) => {
    // Merge incoming payloads with existing state instead of replacing it.
    // Backend heartbeat may not include firewall/system, so preserve what we already have.
    setData((prev) => {
      const merged: WebSocketData = {
        ...(prev || {}),
        ...(newData || {}),
        firewall: {
          ...(prev?.firewall || {}),
          ...(newData?.firewall || {}),
        },
        system: {
          ...(prev?.system || {}),
          ...(newData as any)?.system || {},
        },
      } as WebSocketData;
      return merged;
    });
    setLastError(null);
  }, []);

  const handleStateChange = useCallback((state: string) => {
    setConnectionState(state as any);
    if (state === 'error') {
      setLastError('Connection failed');
    }
  }, []);

  const forceReconnect = useCallback(() => {
    wsRef.current?.forceReconnect();
  }, []);

  useEffect(() => {
    if (!wsRef.current) {
      wsRef.current = new SimpleWebSocket();
      wsRef.current.addListener(handleData);
      wsRef.current.addStateListener(handleStateChange);
      setConnectionState(wsRef.current.getState() as any);
      wsRef.current.connect();
    }
    return () => {
      if (wsRef.current) {
        wsRef.current.removeListener(handleData);
        wsRef.current.removeStateListener(handleStateChange);
        wsRef.current.disconnect();
        wsRef.current = null;
      }
    };
  }, [handleData, handleStateChange]);

  // Poll REST status to enrich WS data with real engine running state.
  useEffect(() => {
    let isMounted = true;
    const controller = new AbortController();

    const pull = async () => {
      try {
        const res = await fetch('/api/system/status', { signal: controller.signal });
        if (!res.ok) return;
        const s = await res.json();
        if (!isMounted) return;
        setData((prev) => {
          const next: WebSocketData = {
            ...(prev || {}),
            firewall: {
              ...(prev?.firewall || {}),
              engine_status: s?.running ? 'running' : 'inactive',
              interface: s?.interface || prev?.firewall?.interface,
              protection_mode: s?.engine_state || prev?.firewall?.protection_mode,
              ebpf_programs: s?.active_programs ?? (prev?.firewall?.ebpf_programs || 0),
              vpp_interfaces: (prev?.firewall?.vpp_interfaces || 0),
              packets_processed: s?.stats?.packets_processed ?? (prev?.firewall?.packets_processed || 0),
              packets_blocked: s?.stats?.packets_dropped ?? (prev?.firewall?.packets_blocked || 0),
            },
            system: {
              ...(prev?.system || {}),
              cpu_usage: s?.stats?.cpu_usage ?? (prev?.system?.cpu_usage || 0),
            },
          } as WebSocketData;
          return next;
        });
      } catch (_) {
        // ignore
      }
    };

    pull();
    const id = window.setInterval(pull, 2000);
    return () => {
      isMounted = false;
      controller.abort();
      clearInterval(id);
    };
  }, []);

  const value: WebSocketContextType = {
    data,
    connectionState,
    isConnected: connectionState === 'connected',
    reconnectCount: 0, // Убираем reconnect счетчик
    lastError,
    forceReconnect
  };

  return (
    <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>
  );
};

export const WebSocketProvider = memo(WSProviderInner);

export const useWebSocket = (): WebSocketContextType => {
  const context = useContext(WebSocketContext);
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};