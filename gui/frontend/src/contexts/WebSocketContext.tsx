// SPDX-License-Identifier: Apache-2.0
// WebSocket Context for real-time communication

import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react';

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
  private url: string = 'ws://localhost:8081/ws';
  private listeners: Set<(data: WebSocketData) => void> = new Set();
  private stateListeners: Set<(state: string) => void> = new Set();
  private reconnectTimer: number | null = null;
  private isDestroyed = false;
  private currentState: string = 'disconnected';

  constructor() {
    console.log('🔧 Создан новый WebSocket экземпляр');
  }

  public connect(): void {
    if (this.isDestroyed || this.ws?.readyState === WebSocket.CONNECTING || this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    this.updateState('connecting');
    console.log('🔌 Подключаемся к WebSocket...');

    try {
      this.ws = new WebSocket(this.url);
      this.ws.onopen = () => {
        console.log('✅ WebSocket подключен успешно!');
        this.updateState('connected');
      };
      
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
      
      this.ws.onclose = (event: CloseEvent) => {
        console.log(`🔌 WebSocket закрыт: code=${event.code}, reason=${event.reason}`);
        this.updateState('disconnected');
      };
      
      this.ws.onerror = (event: Event) => {
        console.error('❌ WebSocket ошибка:', event);
        this.updateState('error');
      };

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

  public forceReconnect(): void {
    console.log('🔄 Принудительное переподключение');
    this.ws?.close();
    setTimeout(() => this.connect(), 1000);
  }

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

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [data, setData] = useState<WebSocketData | null>(null);
  const [connectionState, setConnectionState] = useState<'connecting' | 'connected' | 'disconnected' | 'error' | 'reconnecting'>('disconnected');
  const [lastError, setLastError] = useState<string | null>(null);
  
  const wsRef = useRef<SimpleWebSocket | null>(null);
  
  // Stable callback references
  const handleData = useCallback((newData: WebSocketData) => {
    setData(newData);
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
    // Создаем WebSocket только один раз
    if (!wsRef.current) {
      console.log('🔧 Инициализируем WebSocket в Provider');
      wsRef.current = new SimpleWebSocket();
      wsRef.current.addListener(handleData);
      wsRef.current.addStateListener(handleStateChange);
      
      // Устанавливаем начальное состояние
      setConnectionState(wsRef.current.getState() as any);
      
      // Подключаемся
      wsRef.current.connect();
    }

    // Cleanup при размонтировании
    return () => {
      if (wsRef.current) {
        console.log('🧹 Cleanup WebSocket в Provider');
        wsRef.current.removeListener(handleData);
        wsRef.current.removeStateListener(handleStateChange);
        wsRef.current.disconnect();
        wsRef.current = null;
      }
    };
  }, []); // Пустые deps - выполняется только один раз!

  const value: WebSocketContextType = {
    data,
    connectionState,
    isConnected: connectionState === 'connected',
    reconnectCount: 0, // Убираем reconnect счетчик
    lastError,
    forceReconnect
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = (): WebSocketContextType => {
  const context = useContext(WebSocketContext);
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};