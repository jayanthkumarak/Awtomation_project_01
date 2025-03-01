import React from 'react';
import { NavLink } from 'react-router-dom';
import { useSelector } from 'react-redux';

/**
 * Sidebar navigation component with links to main application sections
 */
const Sidebar = ({ closeSidebar }) => {
  const { latestResults, controls } = useSelector(state => state.compliance);
  
  // Calculate compliance score
  const calculateComplianceScore = () => {
    if (!latestResults || Object.keys(latestResults).length === 0) {
      return 0;
    }
    
    const results = Object.values(latestResults);
    const total = results.length;
    const passing = results.filter(r => r.status === 'PASS').length;
    
    return Math.round((passing / total) * 100);
  };
  
  const score = calculateComplianceScore();
  
  // Get compliance status based on score
  const getComplianceStatus = (score) => {
    if (score >= 80) return { text: 'Good', color: 'text-green-600' };
    if (score >= 50) return { text: 'Fair', color: 'text-yellow-600' };
    return { text: 'Poor', color: 'text-red-600' };
  };
  
  const status = getComplianceStatus(score);
  
  // Navigation items
  const navItems = [
    {
      path: '/',
      name: 'Dashboard',
      icon: (
        <svg className="h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
        </svg>
      ),
    },
    {
      path: '/controls',
      name: 'Controls',
      icon: (
        <svg className="h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
        </svg>
      ),
    },
    {
      path: '/history',
      name: 'History',
      icon: (
        <svg className="h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    {
      path: '/settings',
      name: 'Settings',
      icon: (
        <svg className="h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      ),
    },
  ];
  
  return (
    <div className="flex flex-col h-full bg-white border-r">
      {/* Logo and Title */}
      <div className="p-4 border-b">
        <div className="flex items-center">
          <svg 
            className="h-8 w-8 text-blue-600" 
            xmlns="http://www.w3.org/2000/svg" 
            fill="none" 
            viewBox="0 0 24 24" 
            stroke="currentColor"
          >
            <path 
              strokeLinecap="round" 
              strokeLinejoin="round" 
              strokeWidth={2} 
              d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" 
            />
          </svg>
          <h1 className="ml-2 text-xl font-semibold text-gray-800">CIS Compliance</h1>
          
          {/* Close button for mobile */}
          <button 
            onClick={closeSidebar} 
            className="ml-auto p-1 rounded-full hover:bg-gray-100 md:hidden"
          >
            <svg className="h-6 w-6 text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>
      
      {/* Compliance Score */}
      <div className="p-4 border-b">
        <div className="bg-gray-50 rounded-lg p-3">
          <div className="text-sm text-gray-500 mb-1">Compliance Score</div>
          <div className="flex items-center">
            <div className="text-2xl font-bold">{score}%</div>
            <div className={`ml-2 text-sm font-medium ${status.color}`}>
              {status.text}
            </div>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
            <div 
              className={`h-2 rounded-full ${
                score >= 80 
                  ? 'bg-green-500' 
                  : score >= 50 
                  ? 'bg-yellow-500' 
                  : 'bg-red-500'
              }`} 
              style={{ width: `${score}%` }}
            ></div>
          </div>
        </div>
      </div>
      
      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) => 
              `flex items-center px-4 py-2 text-sm font-medium rounded-md ${
                isActive
                  ? 'bg-blue-50 text-blue-700'
                  : 'text-gray-700 hover:bg-gray-100'
              }`
            }
            onClick={() => {
              if (window.innerWidth < 768) {
                closeSidebar();
              }
            }}
          >
            <div className={`mr-3 ${
              location.pathname === item.path ? 'text-blue-600' : 'text-gray-500'
            }`}>
              {item.icon}
            </div>
            {item.name}
          </NavLink>
        ))}
      </nav>
      
      {/* AWS Account Info */}
      <div className="p-4 border-t">
        <div className="text-xs text-gray-500 mb-1">AWS Account</div>
        <div className="text-sm font-medium text-gray-800">account-12345678</div>
        <div className="text-xs text-gray-500 mt-1">Region: us-east-1</div>
      </div>
    </div>
  );
};

export default Sidebar; 