import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { signOut } from '../../store/authSlice';
import { runComplianceScan } from '../../store/complianceSlice';

/**
 * Header component with app title, scan button, notifications, and user dropdown
 */
const Header = ({ toggleSidebar }) => {
  const dispatch = useDispatch();
  const { user } = useSelector(state => state.auth);
  const { scanInProgress } = useSelector(state => state.compliance);
  
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  
  const handleSignOut = () => {
    dispatch(signOut());
  };
  
  const handleRunScan = () => {
    if (!scanInProgress) {
      dispatch(runComplianceScan());
    }
  };
  
  // Toggle user menu
  const toggleUserMenu = () => {
    setUserMenuOpen(!userMenuOpen);
    if (notificationsOpen) setNotificationsOpen(false);
  };
  
  // Toggle notifications
  const toggleNotifications = () => {
    setNotificationsOpen(!notificationsOpen);
    if (userMenuOpen) setUserMenuOpen(false);
  };
  
  // Sample notifications
  const notifications = [
    { id: 1, message: 'New compliance issues detected', time: '5m ago', read: false },
    { id: 2, message: 'Weekly compliance report ready', time: '1h ago', read: false },
    { id: 3, message: '3 controls remediated successfully', time: '2h ago', read: true },
  ];
  
  return (
    <header className="bg-white border-b border-gray-200">
      <div className="flex items-center justify-between px-4 py-3">
        {/* Left section: Mobile menu button and Logo */}
        <div className="flex items-center">
          <button
            className="md:hidden mr-4 text-gray-500 hover:text-gray-600 focus:outline-none"
            onClick={toggleSidebar}
            aria-label="Open sidebar"
          >
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          
          <Link to="/" className="flex items-center text-blue-600">
            <svg className="h-8 w-8 mr-2" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M20.5 9.5l-9-5.25L2.5 9.5l9 5.25 9-5.25z" fill="currentColor" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M3 9.5v5.25l9 5.25 9-5.25V9.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span className="hidden sm:inline-block text-xl font-semibold">CIS Compliance</span>
          </Link>
        </div>
        
        {/* Right section: Actions, notifications, and user profile */}
        <div className="flex items-center space-x-4">
          {/* Scan button */}
          <button
            className={`px-4 py-2 rounded text-white text-sm font-medium ${
              scanInProgress 
                ? 'bg-gray-400 cursor-not-allowed' 
                : 'bg-blue-600 hover:bg-blue-700'
            }`}
            onClick={handleRunScan}
            disabled={scanInProgress}
          >
            {scanInProgress ? (
              <span className="flex items-center">
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Scanning...
              </span>
            ) : (
              'Run Scan'
            )}
          </button>
          
          {/* Notifications */}
          <div className="relative">
            <button
              className="text-gray-500 hover:text-gray-600 focus:outline-none relative"
              onClick={toggleNotifications}
              aria-label="View notifications"
            >
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
              </svg>
              {/* Notification badge */}
              {notifications.filter(n => !n.read).length > 0 && (
                <span className="absolute top-0 right-0 h-2 w-2 rounded-full bg-red-500"></span>
              )}
            </button>
            
            {/* Notifications dropdown */}
            {notificationsOpen && (
              <div className="absolute right-0 mt-2 w-72 bg-white rounded-md shadow-lg py-1 z-10 border border-gray-200">
                <div className="px-4 py-2 border-b border-gray-200">
                  <p className="text-sm font-medium text-gray-700">Notifications</p>
                </div>
                
                <div className="max-h-96 overflow-y-auto">
                  {notifications.length === 0 ? (
                    <p className="px-4 py-2 text-sm text-gray-500">No notifications</p>
                  ) : (
                    notifications.map(notification => (
                      <div 
                        key={notification.id} 
                        className={`px-4 py-2 hover:bg-gray-50 ${notification.read ? '' : 'bg-blue-50'}`}
                      >
                        <p className="text-sm font-medium text-gray-800">{notification.message}</p>
                        <p className="text-xs text-gray-500 mt-1">{notification.time}</p>
                      </div>
                    ))
                  )}
                </div>
                
                {notifications.length > 0 && (
                  <div className="px-4 py-2 border-t border-gray-200">
                    <button className="text-sm text-blue-500 hover:text-blue-600">
                      Mark all as read
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
          
          {/* User profile */}
          <div className="relative">
            <button
              className="flex items-center space-x-2 focus:outline-none"
              onClick={toggleUserMenu}
              aria-label="User menu"
            >
              <span className="hidden md:block text-sm text-gray-700">{user?.attributes?.name || user?.username || 'User'}</span>
              <div className="h-8 w-8 rounded-full bg-blue-600 flex items-center justify-center text-white">
                {(user?.attributes?.name || user?.username || 'U').charAt(0).toUpperCase()}
              </div>
            </button>
            
            {/* User dropdown menu */}
            {userMenuOpen && (
              <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-10 border border-gray-200">
                <Link
                  to="/settings"
                  className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                  onClick={() => setUserMenuOpen(false)}
                >
                  Settings
                </Link>
                <div className="border-t border-gray-200"></div>
                <button
                  className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                  onClick={handleSignOut}
                >
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header; 