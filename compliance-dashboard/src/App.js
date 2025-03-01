import React, { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { checkAuthState } from './store/authSlice';

// Layout
import Layout from './components/Layout/Layout';

// Pages
import DashboardPage from './pages/DashboardPage';
import ControlsPage from './pages/ControlsPage';
import ControlDetailPage from './pages/ControlDetailPage';
import HistoryPage from './pages/HistoryPage';
import SettingsPage from './pages/SettingsPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import NotFoundPage from './pages/NotFoundPage';

/**
 * Private route component that redirects to login if user is not authenticated
 */
const PrivateRoute = ({ children }) => {
  const { isAuthenticated, isLoading } = useSelector(state => state.auth);
  
  // Show loading spinner while checking auth state
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }
  
  return isAuthenticated ? children : <Navigate to="/login" />;
};

/**
 * Main application component with routing setup
 */
const App = () => {
  const dispatch = useDispatch();
  
  // Check authentication state on app load
  useEffect(() => {
    dispatch(checkAuthState());
  }, [dispatch]);
  
  return (
    <Routes>
      {/* Auth routes */}
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      
      {/* Protected routes with layout */}
      <Route path="/" element={
        <PrivateRoute>
          <Layout />
        </PrivateRoute>
      }>
        <Route index element={<DashboardPage />} />
        <Route path="controls" element={<ControlsPage />} />
        <Route path="controls/:controlId" element={<ControlDetailPage />} />
        <Route path="history" element={<HistoryPage />} />
        <Route path="history/:scanId" element={<DashboardPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
      
      {/* 404 route */}
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
};

export default App; 