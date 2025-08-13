// SPDX-License-Identifier: Apache-2.0
// Authentication Context for VPP eBPF Firewall Dashboard

import React, { createContext, useContext, useState, ReactNode } from 'react';

interface User {
  username: string;
  permissions: string[];
}

interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    // For now, auto-login as admin for development
    return { username: 'admin', permissions: ['read', 'write', 'admin'] };
  });

  const login = async (username: string, password: string): Promise<boolean> => {
    // Simple auth for demo - in production, use real authentication
    if (username === 'admin' && password === 'admin') {
      setUser({ username: 'admin', permissions: ['read', 'write', 'admin'] });
      localStorage.setItem('auth_token', 'demo-token');
      return true;
    }
    return false;
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem('auth_token');
  };

  const value: AuthContextType = {
    user,
    login,
    logout,
    isAuthenticated: !!user,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}; 