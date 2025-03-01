import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { API } from 'aws-amplify';

// Mock API endpoint for settings
const API_NAME = 'complianceApi';
const API_PATH = '/settings';

/**
 * Async thunk to load user settings from the API
 */
export const loadSettings = createAsyncThunk(
  'settings/loadSettings',
  async (_, { rejectWithValue }) => {
    try {
      // In a real app, this would be a call to your API
      // For now, we'll simulate a delay and return mock data
      
      // Uncomment when API is ready:
      // const response = await API.get(API_NAME, API_PATH);
      // return response;
      
      // Mock API response
      await new Promise(resolve => setTimeout(resolve, 500));
      return {
        scanSchedule: 'daily',
        emailNotifications: true,
        notificationEmail: 'admin@example.com',
        retentionPeriod: 90,
        apiKey: 'mock-api-key-123456'
      };
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to load settings');
    }
  }
);

/**
 * Async thunk to save user settings to the API
 */
export const saveSettings = createAsyncThunk(
  'settings/saveSettings',
  async (_, { getState, rejectWithValue }) => {
    try {
      const { settings } = getState();
      const settingsToSave = {
        scanSchedule: settings.scanSchedule,
        emailNotifications: settings.emailNotifications,
        notificationEmail: settings.emailNotifications ? settings.notificationEmail : '',
        retentionPeriod: settings.retentionPeriod
      };
      
      // In a real app, this would be a call to your API
      // For now, we'll simulate a delay
      
      // Uncomment when API is ready:
      // const response = await API.put(API_NAME, API_PATH, {
      //   body: settingsToSave
      // });
      // return response;
      
      // Mock API response
      await new Promise(resolve => setTimeout(resolve, 1000));
      return settingsToSave;
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to save settings');
    }
  }
);

/**
 * Generate a new API key
 */
export const generateApiKey = createAsyncThunk(
  'settings/generateApiKey',
  async (_, { rejectWithValue }) => {
    try {
      // In a real app, this would be a call to your API
      // Uncomment when API is ready:
      // const response = await API.post(API_NAME, `${API_PATH}/api-key`);
      // return response.apiKey;
      
      // Mock API response
      await new Promise(resolve => setTimeout(resolve, 800));
      return `api-key-${Math.random().toString(36).substring(2, 15)}`;
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to generate API key');
    }
  }
);

const settingsSlice = createSlice({
  name: 'settings',
  initialState: {
    scanSchedule: 'daily',
    emailNotifications: false,
    notificationEmail: '',
    retentionPeriod: 90,
    apiKey: '',
    loading: false,
    saveSuccess: false,
    error: null
  },
  reducers: {
    toggleEmailNotifications: (state, action) => {
      state.emailNotifications = action.payload;
      if (!state.emailNotifications) {
        state.error = null; // Clear any email-related errors
      }
    },
    updateEmailAddress: (state, action) => {
      state.notificationEmail = action.payload;
    },
    updateScanSchedule: (state, action) => {
      state.scanSchedule = action.payload;
    },
    updateRetentionPeriod: (state, action) => {
      state.retentionPeriod = action.payload;
    },
    clearSaveSuccess: (state) => {
      state.saveSuccess = false;
    }
  },
  extraReducers: (builder) => {
    builder
      // Load settings cases
      .addCase(loadSettings.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loadSettings.fulfilled, (state, action) => {
        state.loading = false;
        state.scanSchedule = action.payload.scanSchedule;
        state.emailNotifications = action.payload.emailNotifications;
        state.notificationEmail = action.payload.notificationEmail;
        state.retentionPeriod = action.payload.retentionPeriod;
        state.apiKey = action.payload.apiKey;
      })
      .addCase(loadSettings.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // Save settings cases
      .addCase(saveSettings.pending, (state) => {
        state.loading = true;
        state.saveSuccess = false;
        state.error = null;
      })
      .addCase(saveSettings.fulfilled, (state) => {
        state.loading = false;
        state.saveSuccess = true;
      })
      .addCase(saveSettings.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // Generate API key cases
      .addCase(generateApiKey.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(generateApiKey.fulfilled, (state, action) => {
        state.loading = false;
        state.apiKey = action.payload;
      })
      .addCase(generateApiKey.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      });
  }
});

export const { 
  toggleEmailNotifications, 
  updateEmailAddress,
  updateScanSchedule,
  updateRetentionPeriod,
  clearSaveSuccess
} = settingsSlice.actions;

export default settingsSlice.reducer; 