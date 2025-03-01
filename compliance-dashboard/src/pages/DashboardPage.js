import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { startScan, getScanHistory } from '../store/complianceSlice';
import { 
  LineChart, Line, AreaChart, Area, BarChart, Bar, 
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, 
  ResponsiveContainer, PieChart, Pie, Cell 
} from 'recharts';

const DashboardPage = () => {
  const dispatch = useDispatch();
  const { 
    latestResults, 
    scanHistory, 
    controls,
    loading, 
    error,
    lastScanDate
  } = useSelector(state => state.compliance);
  
  const [timeRange, setTimeRange] = useState('7d');
  
  useEffect(() => {
    // Load scan history when component mounts or time range changes
    dispatch(getScanHistory({ timeRange }));
  }, [dispatch, timeRange]);
  
  // Calculate compliance score
  const calculateComplianceScore = () => {
    if (!latestResults || Object.keys(latestResults).length === 0) {
      return { score: 0, total: 0, passing: 0, failing: 0, error: 0 };
    }
    
    const results = Object.values(latestResults);
    const total = results.length;
    const passing = results.filter(r => r.status === 'PASS').length;
    const failing = results.filter(r => r.status === 'FAIL').length;
    const error = results.filter(r => r.status === 'ERROR').length;
    
    const score = Math.round((passing / total) * 100);
    
    return { score, total, passing, failing, error };
  };
  
  const complianceData = calculateComplianceScore();
  
  // Prepare data for pie chart
  const pieChartData = [
    { name: 'Passing', value: complianceData.passing, color: '#10B981' },
    { name: 'Failing', value: complianceData.failing, color: '#EF4444' },
    { name: 'Error', value: complianceData.error, color: '#F59E0B' }
  ].filter(item => item.value > 0);
  
  // Prepare data for category breakdown
  const getCategoryBreakdown = () => {
    if (!controls || !latestResults) return [];
    
    const categories = {};
    
    Object.entries(latestResults).forEach(([controlId, result]) => {
      const control = controls[controlId];
      if (control && control.category) {
        if (!categories[control.category]) {
          categories[control.category] = {
            category: control.category,
            total: 0,
            passing: 0,
            failing: 0,
            error: 0
          };
        }
        
        categories[control.category].total += 1;
        
        if (result.status === 'PASS') {
          categories[control.category].passing += 1;
        } else if (result.status === 'FAIL') {
          categories[control.category].failing += 1;
        } else if (result.status === 'ERROR') {
          categories[control.category].error += 1;
        }
      }
    });
    
    return Object.values(categories).map(cat => ({
      ...cat,
      score: Math.round((cat.passing / cat.total) * 100)
    }));
  };
  
  const categoryData = getCategoryBreakdown();
  
  // Prepare data for trend chart
  const getTrendData = () => {
    if (!scanHistory || scanHistory.length === 0) return [];
    
    return scanHistory.map(scan => {
      const total = scan.control_results ? Object.keys(scan.control_results).length : 0;
      const passing = scan.control_results ? 
        Object.values(scan.control_results).filter(r => r.status === 'PASS').length : 0;
      
      return {
        date: new Date(scan.scan_date).toLocaleDateString(),
        score: Math.round((passing / total) * 100) || 0
      };
    });
  };
  
  const trendData = getTrendData();
  
  // Get critical failing controls
  const getCriticalFailingControls = () => {
    if (!controls || !latestResults) return [];
    
    return Object.entries(latestResults)
      .filter(([controlId, result]) => {
        const control = controls[controlId];
        return control && 
               result.status === 'FAIL' && 
               (control.severity === 'critical' || control.severity === 'high');
      })
      .map(([controlId, result]) => ({
        id: controlId,
        name: controls[controlId].name,
        severity: controls[controlId].severity,
        message: result.message
      }))
      .slice(0, 5); // Get top 5
  };
  
  const criticalFailingControls = getCriticalFailingControls();
  
  // Handle running a new scan
  const handleRunScan = () => {
    dispatch(startScan());
  };
  
  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-800">Compliance Dashboard</h1>
        
        <div className="flex items-center gap-4">
          <div className="text-sm text-gray-500">
            {lastScanDate ? (
              <>Last scan: {new Date(lastScanDate).toLocaleString()}</>
            ) : (
              <>No scans yet</>
            )}
          </div>
          
          <button
            onClick={handleRunScan}
            disabled={loading}
            className="bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-md text-sm font-medium flex items-center"
          >
            {loading ? (
              <>
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Running Scan...
              </>
            ) : (
              <>Run New Scan</>
            )}
          </button>
        </div>
      </div>
      
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6">
          Error: {error}
        </div>
      )}
      
      {/* Score Card */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
        <div className="bg-white rounded-lg shadow-md p-6 col-span-1">
          <h2 className="text-gray-500 text-sm font-medium mb-2">Overall Compliance</h2>
          <div className="flex items-center">
            <div className="text-4xl font-bold text-gray-800">
              {complianceData.score}%
            </div>
            <div className="ml-auto">
              <div className="w-24 h-24">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={30}
                      outerRadius={40}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {pieChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
          <div className="mt-2 grid grid-cols-3 gap-2 text-sm">
            <div>
              <div className="font-medium text-gray-800">{complianceData.passing}</div>
              <div className="text-green-600">Passing</div>
            </div>
            <div>
              <div className="font-medium text-gray-800">{complianceData.failing}</div>
              <div className="text-red-600">Failing</div>
            </div>
            <div>
              <div className="font-medium text-gray-800">{complianceData.error}</div>
              <div className="text-yellow-600">Errors</div>
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow-md col-span-1 md:col-span-3">
          <div className="p-4 border-b">
            <h2 className="font-medium text-gray-700">Compliance Score Trend</h2>
            <div className="flex gap-2 mt-2">
              <button 
                onClick={() => setTimeRange('7d')} 
                className={`text-xs px-2 py-1 rounded ${
                  timeRange === '7d' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-800'
                }`}
              >
                7 Days
              </button>
              <button 
                onClick={() => setTimeRange('30d')} 
                className={`text-xs px-2 py-1 rounded ${
                  timeRange === '30d' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-800'
                }`}
              >
                30 Days
              </button>
              <button 
                onClick={() => setTimeRange('90d')} 
                className={`text-xs px-2 py-1 rounded ${
                  timeRange === '90d' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-800'
                }`}
              >
                90 Days
              </button>
            </div>
          </div>
          <div className="p-4">
            <div className="h-64">
              {trendData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis domain={[0, 100]} />
                    <Tooltip />
                    <Area 
                      type="monotone" 
                      dataKey="score" 
                      stroke="#3B82F6" 
                      fill="#93C5FD" 
                      name="Compliance Score" 
                      unit="%" 
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  No trend data available. Run more scans to see trends.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* Category Breakdown */}
        <div className="bg-white rounded-lg shadow-md">
          <div className="p-4 border-b">
            <h2 className="font-medium text-gray-700">Category Compliance</h2>
          </div>
          <div className="p-4">
            <div className="h-64">
              {categoryData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={categoryData}
                    layout="vertical"
                    margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis type="number" domain={[0, 100]} unit="%" />
                    <YAxis dataKey="category" type="category" width={100} />
                    <Tooltip />
                    <Bar dataKey="score" fill="#3B82F6" name="Compliance Score" unit="%" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-gray-500">
                  No category data available.
                </div>
              )}
            </div>
          </div>
        </div>
        
        {/* Critical Failing Controls */}
        <div className="bg-white rounded-lg shadow-md">
          <div className="p-4 border-b">
            <h2 className="font-medium text-gray-700">Critical Failing Controls</h2>
          </div>
          <div className="p-4">
            {criticalFailingControls.length > 0 ? (
              <div className="divide-y">
                {criticalFailingControls.map(control => (
                  <div key={control.id} className="py-3">
                    <div className="flex items-start">
                      <div className="flex-1">
                        <div className="font-medium text-gray-800">{control.id}: {control.name}</div>
                        <div className="text-sm text-gray-600 mt-1">{control.message}</div>
                      </div>
                      <div>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          control.severity === 'critical' ? 'bg-red-100 text-red-800' : 'bg-orange-100 text-orange-800'
                        }`}>
                          {control.severity}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center justify-center h-64 text-gray-500">
                No critical failing controls. Great job!
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage; 