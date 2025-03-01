import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { 
  setSchedule, 
  toggleEmailNotifications, 
  setNotificationEmail,
  loadSettings,
  saveSettings,
  updateEmailAddress,
  updateScanSchedule
} from '../store/settingsSlice';

/**
 * Settings page component for configuring application preferences
 * Allows users to set scan schedules and notification preferences
 */
const SettingsPage = () => {
  const dispatch = useDispatch();
  const { 
    scanSchedule, 
    emailNotifications, 
    notificationEmail,
    loading,
    error,
    saveSuccess
  } = useSelector(state => state.settings);
  
  const [showSavedMessage, setShowSavedMessage] = useState(false);
  const [emailError, setEmailError] = useState('');
  const [customCron, setCustomCron] = useState('');
  
  // Load existing settings when component mounts
  useEffect(() => {
    dispatch(loadSettings());
  }, [dispatch]);
  
  // Show success message temporarily when settings are saved
  useEffect(() => {
    if (saveSuccess) {
      setShowSavedMessage(true);
      const timer = setTimeout(() => setShowSavedMessage(false), 3000);
      return () => clearTimeout(timer);
    }
  }, [saveSuccess]);
  
  const handleSaveSettings = () => {
    // Validate email if notifications are enabled
    if (emailNotifications && !validateEmail(notificationEmail)) {
      setEmailError('Please enter a valid email address');
      return;
    }
    
    dispatch(saveSettings());
  };
  
  const validateEmail = (email) => {
    const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return re.test(email);
  };
  
  const handleEmailChange = (e) => {
    const email = e.target.value;
    setEmailError('');
    dispatch(updateEmailAddress(email));
  };
  
  const handleToggleNotifications = () => {
    dispatch(toggleEmailNotifications(!emailNotifications));
  };
  
  const handleScheduleChange = (schedule) => {
    dispatch(updateScanSchedule(schedule));
  };
  
  const handleCustomCronChange = (e) => {
    setCustomCron(e.target.value);
  };
  
  const handleApplyCustomCron = () => {
    if (customCron) {
      dispatch(updateScanSchedule(customCron));
    }
  };
  
  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-6">Settings</h1>
      
      {error && (
        <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-6" role="alert">
          <p>{error}</p>
        </div>
      )}
      
      {showSavedMessage && (
        <div className="bg-green-100 border-l-4 border-green-500 text-green-700 p-4 mb-6" role="alert">
          <p>Settings saved successfully!</p>
        </div>
      )}
      
      <div className="bg-white shadow-md rounded-lg p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">Scan Schedule</h2>
        <p className="text-gray-600 mb-4">Set when compliance scans should run automatically.</p>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <button
            className={`p-4 rounded-lg ${scanSchedule === 'daily' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
            onClick={() => handleScheduleChange('daily')}
          >
            Daily
            <span className="block text-sm mt-1">Runs at midnight UTC</span>
          </button>
          
          <button
            className={`p-4 rounded-lg ${scanSchedule === 'weekly' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
            onClick={() => handleScheduleChange('weekly')}
          >
            Weekly
            <span className="block text-sm mt-1">Runs every Monday</span>
          </button>
          
          <button
            className={`p-4 rounded-lg ${scanSchedule === 'monthly' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
            onClick={() => handleScheduleChange('monthly')}
          >
            Monthly
            <span className="block text-sm mt-1">Runs 1st of each month</span>
          </button>
          
          <button
            className={`p-4 rounded-lg ${scanSchedule !== 'daily' && scanSchedule !== 'weekly' && scanSchedule !== 'monthly' ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
            onClick={() => handleScheduleChange('custom')}
          >
            Custom
            <span className="block text-sm mt-1">Set a custom schedule</span>
          </button>
        </div>
        
        {scanSchedule !== 'daily' && scanSchedule !== 'weekly' && scanSchedule !== 'monthly' && (
          <div className="mb-6">
            <label className="block text-gray-700 mb-2">Custom Cron Expression</label>
            <div className="flex">
              <input
                type="text"
                className="flex-grow p-2 border rounded-l-lg"
                placeholder="0 0 * * *"
                value={customCron}
                onChange={handleCustomCronChange}
              />
              <button 
                className="bg-blue-600 text-white px-4 py-2 rounded-r-lg"
                onClick={handleApplyCustomCron}
              >
                Apply
              </button>
            </div>
            <p className="text-sm text-gray-600 mt-2">Use cron expressions (e.g., "0 0 * * *" for daily at midnight)</p>
          </div>
        )}
      </div>
      
      <div className="bg-white shadow-md rounded-lg p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">Notifications</h2>
        <p className="text-gray-600 mb-4">Configure how you'd like to be notified about scan results.</p>
        
        <div className="mb-4">
          <label className="inline-flex items-center cursor-pointer">
            <input 
              type="checkbox"
              className="sr-only"
              checked={emailNotifications}
              onChange={handleToggleNotifications}
            />
            <div className={`h-6 w-11 ${emailNotifications ? 'bg-blue-600' : 'bg-gray-200'} rounded-full p-1 transition-colors duration-300 ease-in-out`}>
              <div className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform duration-300 ease-in-out ${emailNotifications ? 'translate-x-5' : 'translate-x-0'}`}></div>
            </div>
            <span className="ml-3 text-gray-700">Email Notifications</span>
          </label>
        </div>
        
        {emailNotifications && (
          <div className="mb-4">
            <label className="block text-gray-700 mb-2">Email Address</label>
            <input
              type="email"
              className={`w-full p-2 border rounded-lg ${emailError ? 'border-red-500' : 'border-gray-300'}`}
              placeholder="Enter your email"
              value={notificationEmail}
              onChange={handleEmailChange}
            />
            {emailError && <p className="text-red-500 text-sm mt-1">{emailError}</p>}
          </div>
        )}
      </div>
      
      <div className="bg-white shadow-md rounded-lg p-6 mb-8">
        <h2 className="text-xl font-semibold mb-4">Advanced Settings</h2>
        
        <div className="mb-6">
          <h3 className="font-medium mb-2">API Key Management</h3>
          <p className="text-gray-600 mb-3">Manage API keys for external integrations.</p>
          <button className="bg-gray-200 text-gray-700 px-4 py-2 rounded-lg">
            Manage API Keys
          </button>
        </div>
        
        <div className="mb-6">
          <h3 className="font-medium mb-2">Data Retention</h3>
          <p className="text-gray-600 mb-3">Configure how long scan results are kept.</p>
          <select className="w-full p-2 border border-gray-300 rounded-lg">
            <option value="30">30 days</option>
            <option value="60">60 days</option>
            <option value="90">90 days</option>
            <option value="180">180 days</option>
            <option value="365">1 year</option>
          </select>
        </div>
      </div>
      
      <div className="flex justify-end">
        <button 
          className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 disabled:bg-gray-400"
          onClick={handleSaveSettings}
          disabled={loading}
        >
          {loading ? 'Saving...' : 'Save Settings'}
        </button>
      </div>
    </div>
  );
};

export default SettingsPage; 