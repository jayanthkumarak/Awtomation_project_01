import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';

// Icons (would normally use a proper icon library like react-icons or heroicons)
const DashboardIcon = () => <span>📊</span>;
const ControlsIcon = () => <span>🛡️</span>;
const HistoryIcon = () => <span>📜</span>;
const SettingsIcon = () => <span>⚙️</span>;

const Navigation = ({ user, signOut }) => {
  const [collapsed, setCollapsed] = useState(false);

  const toggleSidebar = () => {
    setCollapsed(!collapsed);
  };

  return (
    <nav className={`bg-gray-800 text-white ${collapsed ? 'w-16' : 'w-64'} transition-all duration-300 flex flex-col`}>
      <div className="p-4 border-b border-gray-700 flex items-center justify-between">
        {!collapsed && <h1 className="text-xl font-bold">CIS Compliance</h1>}
        <button 
          onClick={toggleSidebar}
          className="p-2 rounded-md hover:bg-gray-700 focus:outline-none"
        >
          {collapsed ? '→' : '←'}
        </button>
      </div>
      
      <div className="flex-1 py-6">
        <ul className="space-y-2">
          <li>
            <NavLink 
              to="/" 
              className={({ isActive }) => 
                `flex items-center p-3 ${collapsed ? 'justify-center' : 'px-4'} 
                 hover:bg-gray-700 ${isActive ? 'bg-gray-700' : ''}`
              }
            >
              <DashboardIcon />
              {!collapsed && <span className="ml-3">Dashboard</span>}
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/controls" 
              className={({ isActive }) => 
                `flex items-center p-3 ${collapsed ? 'justify-center' : 'px-4'} 
                 hover:bg-gray-700 ${isActive ? 'bg-gray-700' : ''}`
              }
            >
              <ControlsIcon />
              {!collapsed && <span className="ml-3">Controls</span>}
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/history" 
              className={({ isActive }) => 
                `flex items-center p-3 ${collapsed ? 'justify-center' : 'px-4'} 
                 hover:bg-gray-700 ${isActive ? 'bg-gray-700' : ''}`
              }
            >
              <HistoryIcon />
              {!collapsed && <span className="ml-3">History</span>}
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/settings" 
              className={({ isActive }) => 
                `flex items-center p-3 ${collapsed ? 'justify-center' : 'px-4'} 
                 hover:bg-gray-700 ${isActive ? 'bg-gray-700' : ''}`
              }
            >
              <SettingsIcon />
              {!collapsed && <span className="ml-3">Settings</span>}
            </NavLink>
          </li>
        </ul>
      </div>
      
      <div className="p-4 border-t border-gray-700">
        {!collapsed ? (
          <div>
            <div className="text-sm text-gray-300 mb-2">
              Signed in as
              <div className="font-bold">{user?.username || 'User'}</div>
            </div>
            <button 
              onClick={signOut}
              className="w-full bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded-md"
            >
              Sign Out
            </button>
          </div>
        ) : (
          <button 
            onClick={signOut}
            className="w-full flex justify-center py-2 text-red-400 hover:text-red-300"
            title="Sign Out"
          >
            <span>🚪</span>
          </button>
        )}
      </div>
    </nav>
  );
};

export default Navigation; 