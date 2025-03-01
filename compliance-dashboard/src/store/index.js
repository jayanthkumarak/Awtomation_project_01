import { configureStore } from '@reduxjs/toolkit';
import settingsReducer from './settingsSlice';
import complianceReducer from './complianceSlice';
import authReducer from './authSlice';

/**
 * Redux store configuration
 * Combines multiple reducers for different features of the application
 */
const store = configureStore({
  reducer: {
    settings: settingsReducer,
    compliance: complianceReducer,
    auth: authReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: false, // Disable serializable check for AWS Amplify integration
    }),
});

export default store; 