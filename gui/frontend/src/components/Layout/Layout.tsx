import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopBar from './TopBar';

const Layout: React.FC = () => {
  const [mobileOpen, setMobileOpen] = useState(false);
  
  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };
  
  const handleMenuClick = () => {
    // Handle menu click
  };
  
  return (
    <div className="flex h-screen bg-gray-100">
      <Sidebar 
        width={240}
        mobileOpen={mobileOpen}
        onDrawerToggle={handleDrawerToggle}
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar onMenuClick={handleMenuClick} />
        <main className="flex-1 overflow-x-hidden overflow-y-auto bg-gray-100">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout; 