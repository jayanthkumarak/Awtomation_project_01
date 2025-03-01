import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { API } from 'aws-amplify';

// Mock API endpoint for compliance
const API_NAME = 'complianceApi';
const SCANS_PATH = '/scans';
const REMEDIATE_PATH = '/remediate';

/**
 * Async thunk to run a new compliance scan
 */
export const runComplianceScan = createAsyncThunk(
  'compliance/runScan',
  async (_, { rejectWithValue }) => {
    try {
      // In a real app, this would be a call to your API
      // Uncomment when API is ready:
      // const response = await API.post(API_NAME, SCANS_PATH);
      // return response;
      
      // Mock API response with delay to simulate scan
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Generate mock scan results
      const mockResults = {
        scanId: `scan-${Date.now()}`,
        timestamp: new Date().toISOString(),
        summary: {
          totalChecks: 25,
          passedChecks: 18,
          failedChecks: 5,
          warningChecks: 2,
          complianceScore: 72,
        },
        controls: generateMockControls(),
      };
      
      return mockResults;
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to run compliance scan');
    }
  }
);

/**
 * Async thunk to load compliance scan history
 */
export const loadScanHistory = createAsyncThunk(
  'compliance/loadHistory',
  async (_, { rejectWithValue }) => {
    try {
      // In a real app, this would be a call to your API
      // Uncomment when API is ready:
      // const response = await API.get(API_NAME, SCANS_PATH);
      // return response;
      
      // Mock API response
      await new Promise(resolve => setTimeout(resolve, 800));
      
      // Generate mock scan history (last 6 scans)
      const history = [];
      const now = new Date();
      
      for (let i = 0; i < 6; i++) {
        const date = new Date(now);
        date.setDate(date.getDate() - i * 5); // Every 5 days
        
        const passedChecks = 18 + Math.floor(Math.random() * 7) - 3; // Between 15-22
        const totalChecks = 25;
        
        history.push({
          scanId: `scan-${date.getTime()}`,
          timestamp: date.toISOString(),
          summary: {
            totalChecks,
            passedChecks,
            failedChecks: totalChecks - passedChecks - Math.floor(Math.random() * 3),
            warningChecks: Math.floor(Math.random() * 3),
            complianceScore: Math.round((passedChecks / totalChecks) * 100),
          }
        });
      }
      
      return history.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to load scan history');
    }
  }
);

/**
 * Async thunk to load a specific scan result by ID
 */
export const loadScanById = createAsyncThunk(
  'compliance/loadScanById',
  async (scanId, { rejectWithValue }) => {
    try {
      // In a real app, this would be a call to your API
      // Uncomment when API is ready:
      // const response = await API.get(API_NAME, `${SCANS_PATH}/${scanId}`);
      // return response;
      
      // Mock API response
      await new Promise(resolve => setTimeout(resolve, 600));
      
      // Generate a consistent mock result for the given scan ID
      const seedValue = parseInt(scanId.replace('scan-', ''));
      const mockResults = {
        scanId,
        timestamp: new Date(seedValue).toISOString(),
        summary: {
          totalChecks: 25,
          passedChecks: 18,
          failedChecks: 5,
          warningChecks: 2,
          complianceScore: 72,
        },
        controls: generateMockControls(seedValue),
      };
      
      return mockResults;
    } catch (error) {
      return rejectWithValue(error.message || 'Failed to load scan results');
    }
  }
);

/**
 * Async thunk to remediate a non-compliant control
 */
export const remediateControl = createAsyncThunk(
  'compliance/remediateControl',
  async ({ controlId, scanId }, { rejectWithValue }) => {
    try {
      // In a real app, this would be a call to your API
      // Uncomment when API is ready:
      // const response = await API.post(API_NAME, REMEDIATE_PATH, {
      //   body: { controlId, scanId }
      // });
      // return response;
      
      // Mock API response with delay to simulate remediation
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      return {
        controlId,
        scanId,
        success: true,
        message: `Successfully remediated control ${controlId}`
      };
    } catch (error) {
      return rejectWithValue(error.message || `Failed to remediate control ${controlId}`);
    }
  }
);

// Helper function to generate mock controls
function generateMockControls(seed = Date.now()) {
  const random = (min, max) => {
    const x = Math.sin(seed++) * 10000;
    return Math.floor((x - Math.floor(x)) * (max - min + 1)) + min;
  };
  
  const controls = [];
  const categories = ['IAM', 'Logging', 'Monitoring', 'Networking', 'Storage'];
  const statuses = ['PASSED', 'FAILED', 'WARNING'];
  const statusWeights = [0.7, 0.2, 0.1]; // 70% pass, 20% fail, 10% warning
  
  for (let i = 1; i <= 25; i++) {
    const category = categories[i % categories.length];
    
    // Determine status based on weights
    let status;
    const roll = Math.random();
    if (roll < statusWeights[0]) {
      status = statuses[0]; // PASSED
    } else if (roll < statusWeights[0] + statusWeights[1]) {
      status = statuses[1]; // FAILED
    } else {
      status = statuses[2]; // WARNING
    }
    
    const hasRemediation = status === 'FAILED' && Math.random() > 0.3;
    
    controls.push({
      id: `${category}.${i}`,
      name: `Ensure ${category} security best practice ${i}`,
      description: `This control checks that ${category.toLowerCase()} resources follow security best practices.`,
      category,
      status,
      severity: ['LOW', 'MEDIUM', 'HIGH'][random(0, 2)],
      details: status === 'PASSED' 
        ? 'Control requirements are satisfied.' 
        : `Found ${random(1, 5)} resource(s) not compliant with this control.`,
      remediation: hasRemediation ? {
        available: true,
        description: `Automated remediation is available for this control.`
      } : {
        available: false,
        description: 'This control requires manual remediation.'
      }
    });
  }
  
  return controls;
}

const complianceSlice = createSlice({
  name: 'compliance',
  initialState: {
    currentScan: null,
    scanHistory: [],
    selectedScan: null,
    loading: false,
    scanInProgress: false,
    remediationInProgress: false,
    error: null,
    remediationStatus: null
  },
  reducers: {
    clearCurrentScan: (state) => {
      state.currentScan = null;
    },
    setSelectedScan: (state, action) => {
      state.selectedScan = action.payload;
    },
    clearRemediationStatus: (state) => {
      state.remediationStatus = null;
    }
  },
  extraReducers: (builder) => {
    builder
      // Run scan cases
      .addCase(runComplianceScan.pending, (state) => {
        state.loading = true;
        state.scanInProgress = true;
        state.error = null;
      })
      .addCase(runComplianceScan.fulfilled, (state, action) => {
        state.loading = false;
        state.scanInProgress = false;
        state.currentScan = action.payload;
        // Add to history if not already present
        if (!state.scanHistory.find(scan => scan.scanId === action.payload.scanId)) {
          state.scanHistory.unshift({
            scanId: action.payload.scanId,
            timestamp: action.payload.timestamp,
            summary: action.payload.summary
          });
        }
      })
      .addCase(runComplianceScan.rejected, (state, action) => {
        state.loading = false;
        state.scanInProgress = false;
        state.error = action.payload;
      })
      
      // Load history cases
      .addCase(loadScanHistory.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loadScanHistory.fulfilled, (state, action) => {
        state.loading = false;
        state.scanHistory = action.payload;
      })
      .addCase(loadScanHistory.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // Load scan by ID cases
      .addCase(loadScanById.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(loadScanById.fulfilled, (state, action) => {
        state.loading = false;
        state.selectedScan = action.payload;
      })
      .addCase(loadScanById.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      })
      
      // Remediate control cases
      .addCase(remediateControl.pending, (state) => {
        state.remediationInProgress = true;
        state.error = null;
      })
      .addCase(remediateControl.fulfilled, (state, action) => {
        state.remediationInProgress = false;
        state.remediationStatus = {
          success: true,
          message: action.payload.message,
          controlId: action.payload.controlId
        };
        
        // Update control status in current scan and selected scan
        const updateScanControls = (scan) => {
          if (!scan || !scan.controls) return;
          
          const controlIndex = scan.controls.findIndex(c => c.id === action.payload.controlId);
          if (controlIndex !== -1) {
            scan.controls[controlIndex].status = 'PASSED';
            scan.controls[controlIndex].details = 'Control remediated successfully';
            
            // Update summary
            scan.summary.passedChecks += 1;
            scan.summary.failedChecks -= 1;
            scan.summary.complianceScore = Math.round(
              (scan.summary.passedChecks / scan.summary.totalChecks) * 100
            );
          }
        };
        
        updateScanControls(state.currentScan);
        updateScanControls(state.selectedScan);
      })
      .addCase(remediateControl.rejected, (state, action) => {
        state.remediationInProgress = false;
        state.remediationStatus = {
          success: false,
          message: action.payload
        };
      });
  }
});

export const { 
  clearCurrentScan,
  setSelectedScan,
  clearRemediationStatus 
} = complianceSlice.actions;

export default complianceSlice.reducer; 