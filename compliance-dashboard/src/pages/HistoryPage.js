import React, { useState, useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { getScanHistory, loadScanResults } from '../store/complianceSlice';
import { format } from 'date-fns';

const HistoryPage = () => {
  const dispatch = useDispatch();
  const { scanHistory, loading, error } = useSelector(state => state.compliance);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [timeRange, setTimeRange] = useState('30d');
  
  useEffect(() => {
    dispatch(getScanHistory({ timeRange }));
  }, [dispatch, timeRange]);
  
  // Calculate compliance score for a scan
  const calculateComplianceScore = (scan) => {
    if (!scan || !scan.control_results) return 0;
    
    const results = Object.values(scan.control_results);
    const total = results.length;
    if (total === 0) return 0;
    
    const passing = results.filter(r => r.status === 'PASS').length;
    return Math.round((passing / total) * 100);
  };
  
  // Handle viewing a specific scan
  const handleViewScan = (scanId) => {
    setSelectedScanId(scanId);
    dispatch(loadScanResults({ scanId }));
  };
  
  // Get selected scan
  const selectedScan = scanHistory.find(scan => scan.id === selectedScanId);
  
  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-800 mb-6">Scan History</h1>
      
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6">
          Error: {error}
        </div>
      )}
      
      {/* Time range filter */}
      <div className="mb-6">
        <div className="inline-flex rounded-md shadow-sm" role="group">
          <button
            type="button"
            onClick={() => setTimeRange('7d')}
            className={`px-4 py-2 text-sm font-medium rounded-l-lg ${
              timeRange === '7d'
                ? 'bg-blue-600 text-white'
                : 'bg-white text-gray-700 hover:bg-gray-50'
            }`}
          >
            Last 7 Days
          </button>
          <button
            type="button"
            onClick={() => setTimeRange('30d')}
            className={`px-4 py-2 text-sm font-medium ${
              timeRange === '30d'
                ? 'bg-blue-600 text-white'
                : 'bg-white text-gray-700 hover:bg-gray-50'
            }`}
          >
            Last 30 Days
          </button>
          <button
            type="button"
            onClick={() => setTimeRange('90d')}
            className={`px-4 py-2 text-sm font-medium rounded-r-lg ${
              timeRange === '90d'
                ? 'bg-blue-600 text-white'
                : 'bg-white text-gray-700 hover:bg-gray-50'
            }`}
          >
            Last 90 Days
          </button>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Scans List */}
        <div className="md:col-span-1">
          <div className="bg-white rounded-lg shadow-md overflow-hidden">
            <div className="p-4 border-b">
              <h2 className="font-medium text-gray-700">Scans</h2>
            </div>
            
            {loading ? (
              <div className="p-4 text-center">
                <svg className="animate-spin h-5 w-5 text-blue-500 mx-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <p className="mt-2 text-gray-500">Loading scans...</p>
              </div>
            ) : scanHistory.length > 0 ? (
              <div className="divide-y">
                {scanHistory.map(scan => (
                  <div 
                    key={scan.id} 
                    className={`p-4 cursor-pointer hover:bg-gray-50 ${
                      selectedScanId === scan.id ? 'bg-blue-50' : ''
                    }`}
                    onClick={() => handleViewScan(scan.id)}
                  >
                    <div className="flex justify-between items-center">
                      <div className="flex-1">
                        <div className="text-sm text-gray-500">
                          {format(new Date(scan.scan_date), 'MMM d, yyyy HH:mm')}
                        </div>
                        <div className="font-medium text-gray-800 mt-1">
                          Score: {calculateComplianceScore(scan)}%
                        </div>
                      </div>
                      <svg className="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" />
                      </svg>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center text-gray-500">
                No scan history found in the selected time range.
              </div>
            )}
          </div>
        </div>
        
        {/* Scan Detail */}
        <div className="md:col-span-2">
          {selectedScan ? (
            <div className="bg-white rounded-lg shadow-md">
              <div className="p-4 border-b">
                <h2 className="font-medium text-gray-700">
                  Scan Details - {format(new Date(selectedScan.scan_date), 'MMMM d, yyyy HH:mm:ss')}
                </h2>
              </div>
              
              <div className="p-4">
                <div className="grid grid-cols-3 gap-4 mb-6">
                  <div className="bg-gray-50 p-4 rounded-lg">
                    <div className="text-sm text-gray-500">Score</div>
                    <div className="text-2xl font-bold text-gray-800">
                      {calculateComplianceScore(selectedScan)}%
                    </div>
                  </div>
                  
                  <div className="bg-gray-50 p-4 rounded-lg">
                    <div className="text-sm text-gray-500">Controls Passing</div>
                    <div className="text-2xl font-bold text-green-600">
                      {selectedScan.control_results 
                        ? Object.values(selectedScan.control_results).filter(r => r.status === 'PASS').length 
                        : 0}
                    </div>
                  </div>
                  
                  <div className="bg-gray-50 p-4 rounded-lg">
                    <div className="text-sm text-gray-500">Controls Failing</div>
                    <div className="text-2xl font-bold text-red-600">
                      {selectedScan.control_results 
                        ? Object.values(selectedScan.control_results).filter(r => r.status === 'FAIL').length 
                        : 0}
                    </div>
                  </div>
                </div>
                
                <div className="mb-4">
                  <h3 className="text-lg font-medium text-gray-700 mb-2">Control Results</h3>
                  
                  {selectedScan.control_results ? (
                    <div className="bg-white border rounded-lg overflow-hidden">
                      <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                          <tr>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Control ID
                            </th>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Status
                            </th>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                              Message
                            </th>
                          </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                          {Object.entries(selectedScan.control_results).map(([controlId, result]) => (
                            <tr key={controlId}>
                              <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                {controlId}
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap text-sm">
                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                  result.status === 'PASS' 
                                    ? 'bg-green-100 text-green-800'
                                    : result.status === 'FAIL'
                                    ? 'bg-red-100 text-red-800'
                                    : 'bg-yellow-100 text-yellow-800'
                                }`}>
                                  {result.status}
                                </span>
                              </td>
                              <td className="px-6 py-4 text-sm text-gray-500">
                                {result.message}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="text-gray-500">No control results available for this scan.</div>
                  )}
                </div>
                
                <div>
                  <h3 className="text-lg font-medium text-gray-700 mb-2">Metadata</h3>
                  <div className="bg-gray-50 p-4 rounded-lg">
                    <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-2">
                      <div>
                        <dt className="text-sm font-medium text-gray-500">Scan ID</dt>
                        <dd className="mt-1 text-sm text-gray-900">{selectedScan.id}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-500">Account ID</dt>
                        <dd className="mt-1 text-sm text-gray-900">{selectedScan.account_id || 'N/A'}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-500">Region</dt>
                        <dd className="mt-1 text-sm text-gray-900">{selectedScan.region || 'N/A'}</dd>
                      </div>
                      <div>
                        <dt className="text-sm font-medium text-gray-500">Duration</dt>
                        <dd className="mt-1 text-sm text-gray-900">
                          {selectedScan.duration ? `${selectedScan.duration} seconds` : 'N/A'}
                        </dd>
                      </div>
                    </dl>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-white rounded-lg shadow-md p-8 text-center">
              <svg className="h-12 w-12 text-gray-400 mx-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
              <h3 className="mt-2 text-sm font-medium text-gray-900">No scan selected</h3>
              <p className="mt-1 text-sm text-gray-500">
                Select a scan from the list to view its details.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default HistoryPage; 