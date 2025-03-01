import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Header from './Header';
import Sidebar from './Sidebar';

/**
 * Layout component that provides the overall structure for the application
 * Includes responsive header, sidebar, and content area
 */
const Layout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  
  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };
  
  return (
    <div className="flex h-screen bg-gray-100">
      {/* Sidebar - mobile version with overlay */}
      <div className={`md:hidden fixed inset-0 z-20 bg-black bg-opacity-50 transition-opacity ${
        sidebarOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'
      }`} onClick={toggleSidebar}></div>
      
      {/* Sidebar component - responsive behavior */}
      <div className={`fixed md:static inset-y-0 left-0 z-30 w-64 bg-blue-800 text-white transition-transform duration-300 transform ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
      }`}>
        <Sidebar closeSidebar={() => setSidebarOpen(false)} />
      </div>
      
      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header toggleSidebar={toggleSidebar} />
        
        {/* Main content area */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          <Outlet />
        </main>
        
        {/* Footer */}
        <footer className="bg-white p-4 border-t text-center text-gray-500 text-sm">
          CIS AWS Compliance Dashboard &copy; {new Date().getFullYear()}
        </footer>
      </div>
    </div>
  );
};

export default Layout; 