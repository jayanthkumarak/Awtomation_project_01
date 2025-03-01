import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { Auth } from 'aws-amplify';

/**
 * Async thunk to sign in a user
 */
export const signIn = createAsyncThunk(
  'auth/signIn',
  async ({ username, password }, { rejectWithValue }) => {
    try {
      // In a real app with AWS Amplify, use:
      // const user = await Auth.signIn(username, password);
      // return user;
      
      // For development without actual AWS Amplify setup:
      await new Promise(resolve => setTimeout(resolve, 800));
      
      // Mock successful authentication
      if (username === 'admin@example.com' && password === 'password') {
        return {
          username: 'admin@example.com',
          attributes: {
            email: 'admin@example.com',
            name: 'Admin User',
          },
          signInUserSession: {
            idToken: { jwtToken: 'mock-token' },
          }
        };
      }
      
      throw new Error('Invalid username or password');
    } catch (error) {
      return rejectWithValue(error.message || 'Authentication failed');
    }
  }
);

/**
 * Async thunk to sign out a user
 */
export const signOut = createAsyncThunk(
  'auth/signOut',
  async (_, { rejectWithValue }) => {
    try {
      // In a real app with AWS Amplify, use:
      // await Auth.signOut();
      
      // For development without actual AWS Amplify setup:
      await new Promise(resolve => setTimeout(resolve, 500));
      return true;
    } catch (error) {
      return rejectWithValue(error.message || 'Sign out failed');
    }
  }
);

/**
 * Async thunk to check current authenticated session
 */
export const checkAuthState = createAsyncThunk(
  'auth/checkAuthState',
  async (_, { rejectWithValue }) => {
    try {
      // In a real app with AWS Amplify, use:
      // const user = await Auth.currentAuthenticatedUser();
      // return user;
      
      // For development without actual AWS Amplify setup:
      await new Promise(resolve => setTimeout(resolve, 300));
      
      // Mock user session (would normally check localStorage or tokens)
      const isAuthenticated = localStorage.getItem('isAuthenticated') === 'true';
      
      if (isAuthenticated) {
        return {
          username: 'admin@example.com',
          attributes: {
            email: 'admin@example.com',
            name: 'Admin User',
          }
        };
      }
      
      throw new Error('No current user');
    } catch (error) {
      return rejectWithValue(null); // Not throwing an error as this is an expected case
    }
  }
);

/**
 * Async thunk to register a new user
 */
export const signUp = createAsyncThunk(
  'auth/signUp',
  async ({ username, password, email, name }, { rejectWithValue }) => {
    try {
      // In a real app with AWS Amplify, use:
      // const { user } = await Auth.signUp({
      //   username,
      //   password,
      //   attributes: {
      //     email,
      //     name,
      //   }
      // });
      // return user;
      
      // For development without actual AWS Amplify setup:
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      return {
        username,
        userConfirmed: false,
        userSub: `mock-sub-${Date.now()}`
      };
    } catch (error) {
      return rejectWithValue(error.message || 'Registration failed');
    }
  }
);

/**
 * Async thunk to confirm user registration
 */
export const confirmSignUp = createAsyncThunk(
  'auth/confirmSignUp',
  async ({ username, code }, { rejectWithValue }) => {
    try {
      // In a real app with AWS Amplify, use:
      // await Auth.confirmSignUp(username, code);
      
      // For development without actual AWS Amplify setup:
      await new Promise(resolve => setTimeout(resolve, 800));
      
      // Mock validation logic
      if (code === '123456' || code === '000000') {
        return true;
      }
      
      throw new Error('Invalid verification code');
    } catch (error) {
      return rejectWithValue(error.message || 'Confirmation failed');
    }
  }
);

const authSlice = createSlice({
  name: 'auth',
  initialState: {
    user: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
    signUpSuccess: false,
    confirmationSuccess: false,
  },
  reducers: {
    clearAuthError: (state) => {
      state.error = null;
    },
    clearSignUpSuccess: (state) => {
      state.signUpSuccess = false;
    },
    clearConfirmationSuccess: (state) => {
      state.confirmationSuccess = false;
    }
  },
  extraReducers: (builder) => {
    builder
      // Check auth state cases
      .addCase(checkAuthState.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(checkAuthState.fulfilled, (state, action) => {
        state.isLoading = false;
        state.user = action.payload;
        state.isAuthenticated = !!action.payload;
      })
      .addCase(checkAuthState.rejected, (state) => {
        state.isLoading = false;
        state.user = null;
        state.isAuthenticated = false;
      })
      
      // Sign in cases
      .addCase(signIn.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(signIn.fulfilled, (state, action) => {
        state.isLoading = false;
        state.user = action.payload;
        state.isAuthenticated = true;
        // Store auth state in localStorage for persistence
        localStorage.setItem('isAuthenticated', 'true');
      })
      .addCase(signIn.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Sign out cases
      .addCase(signOut.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(signOut.fulfilled, (state) => {
        state.isLoading = false;
        state.user = null;
        state.isAuthenticated = false;
        localStorage.removeItem('isAuthenticated');
      })
      .addCase(signOut.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Sign up cases
      .addCase(signUp.pending, (state) => {
        state.isLoading = true;
        state.error = null;
        state.signUpSuccess = false;
      })
      .addCase(signUp.fulfilled, (state) => {
        state.isLoading = false;
        state.signUpSuccess = true;
      })
      .addCase(signUp.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      })
      
      // Confirm sign up cases
      .addCase(confirmSignUp.pending, (state) => {
        state.isLoading = true;
        state.error = null;
        state.confirmationSuccess = false;
      })
      .addCase(confirmSignUp.fulfilled, (state) => {
        state.isLoading = false;
        state.confirmationSuccess = true;
      })
      .addCase(confirmSignUp.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload;
      });
  }
});

export const { 
  clearAuthError, 
  clearSignUpSuccess,
  clearConfirmationSuccess
} = authSlice.actions;

export default authSlice.reducer; 