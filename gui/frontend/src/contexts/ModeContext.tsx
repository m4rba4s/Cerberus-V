import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
// Simple API service for mode management
interface ModeResponse {
  mode: 'simulation' | 'live';
  success: boolean;
  message?: string;
}

const apiService = {
  getMode: async (): Promise<ModeResponse> => {
    try {
      const response = await fetch('/api/health');
      const data = await response.json();
      return { mode: data.mode || 'simulation', success: true };
    } catch (error) {
      return { mode: 'simulation', success: false, message: 'Failed to get mode' };
    }
  },
  
  setMode: async (mode: 'simulation' | 'live'): Promise<ModeResponse> => {
    try {
      const response = await fetch('/api/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
      });
      const data = await response.json();
      return { mode: data.mode || mode, success: true };
    } catch (error) {
      return { mode: 'simulation', success: false, message: 'Failed to set mode' };
    }
  }
};

interface ModeContextType {
  mode: 'simulation' | 'live';
  setMode: (mode: 'simulation' | 'live') => Promise<void>;
  isLive: boolean;
  error: string | null;
  setError: (error: string | null) => void;
  _loading: boolean;
  refreshMode: () => Promise<void>;
}

const ModeContext = createContext<ModeContextType | undefined>(undefined);

export const useMode = () => {
  const context = useContext(ModeContext);
  if (context === undefined) {
    throw new Error('useMode must be used within a ModeProvider');
  }
  return context;
};

interface ModeProviderProps {
  children: ReactNode;
}

export const ModeProvider: React.FC<ModeProviderProps> = ({ children }) => {
  const [mode, setModeState] = useState<'simulation' | 'live'>('simulation');
  const [error, setError] = useState<string | null>(null);
  const [_loading, _setLoading] = useState(false);

  const refreshMode = async () => {
    try {
      _setLoading(true);
      setError(null);
      const response = await apiService.getMode();
      setModeState(response.mode);
    } catch (err) {
      console.error('Failed to get mode:', err);
      setError(err instanceof Error ? err.message : 'Failed to get mode');
      // Fallback to simulation mode if API fails
      setModeState('simulation');
    } finally {
      _setLoading(false);
    }
  };

  const setMode = async (newMode: 'simulation' | 'live') => {
    try {
      _setLoading(true);
      setError(null);
      
      const response = await apiService.setMode(newMode);
      
      if (response.success) {
        setModeState(response.mode);
      } else {
        throw new Error(response.message);
      }
    } catch (err) {
      console.error('Failed to set mode:', err);
      setError(err instanceof Error ? err.message : 'Failed to set mode');
      throw err; // Re-throw to let UI handle the error
    } finally {
      _setLoading(false);
    }
  };

  // Initialize mode on mount
  useEffect(() => {
    refreshMode();
  }, []);

  // Poll for mode changes every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      refreshMode();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const value: ModeContextType = {
    mode,
    setMode,
    isLive: mode === 'live',
    error,
    setError,
    _loading,
    refreshMode,
  };

  return (
    <ModeContext.Provider value={value}>
      {children}
    </ModeContext.Provider>
  );
}; 