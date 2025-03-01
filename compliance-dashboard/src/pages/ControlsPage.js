import React, { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { selectControl, remediateControl } from '../store/complianceSlice';

const ControlsPage = () => {
  const dispatch = useDispatch();
  const { controls, latestResults, loading, selectedControl } = useSelector(state => state.compliance);
  
  // Local state for filtering and sorting
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sortBy, setSortBy] = useState('controlId');
  const [sortDirection, setSortDirection] = useState('asc');
  
  // Prepare data for the controls table
  const controlIds = Object.keys(controls);
  const uniqueCategories = [...new Set(Object.values(controls).map(control => control.category))];
  
  // Filter and sort controls
  const filteredControls = controlIds
    .filter(controlId => {
      const control = controls[controlId];
      const result = latestResults[controlId] || {};
      
      const matchesSearch = searchTerm === '' || 
        controlId.toLowerCase().includes(searchTerm.toLowerCase()) ||
        control.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        control.description.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesCategory = categoryFilter === '' || control.category === categoryFilter;
      const matchesStatus = statusFilter === '' || result.status === statusFilter;
      
      return matchesSearch && matchesCategory && matchesStatus;
    })
    .sort((a, b) => {
      const controlA = controls[a];
      const controlB = controls[b];
      const resultA = latestResults[a] || {};
      const resultB = latestResults[b] || {};
      
      let valueA, valueB;
      
      switch (sortBy) {
        case 'controlId':
          valueA = a;
          valueB = b;
          break;
        case 'name':
          valueA = controlA.name;
          valueB = controlB.name;
          break;
        case 'category':
          valueA = controlA.category;
          valueB = controlB.category;
          break;
        case 'severity':
          valueA = controlA.severity;
          valueB = controlB.severity;
          break;
        case 'status':
          valueA = resultA.status || '';
          valueB = resultB.status || '';
          break;
        default:
          valueA = a;
          valueB = b;
      }
      
      if (valueA < valueB) return sortDirection === 'asc' ? -1 : 1;
      if (valueA > valueB) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  
  // Handle sort change
  const handleSort = (column) => {
    if (sortBy === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(column);
      setSortDirection('asc');
    }
  };
  
  // Handle remediation
  const handleRemediate = (controlId) => {
    const confirmRemediation = window.confirm(
      'Are you sure you want to remediate this control? This will make changes to your AWS resources.'
    );
    
    if (confirmRemediation) {
      dispatch(remediateControl({ control_id: controlId }));
    }
  };
  
  // Handle selecting a control for detail view
  const handleSelectControl = (controlId) => {
    dispatch(selectControl(controlId === selectedControl ? null : controlId));
  };
  
  // Render status badge
  const renderStatusBadge = (status) => {
    if (!status) return null;
    
    let classes = '';
    switch (status) {
      case 'PASS':
        classes = 'status-pass';
        break;
      case 'FAIL':
        classes = 'status-fail';
        break;
      case 'ERROR':
        classes = 'status-error';
        break;
      default:
        classes = 'bg-gray-100 text-gray-800 rounded-full px-3 py-1 text-sm font-medium';
    }
    
    return <span className={classes}>{status}</span>;
  };
  
  // Render severity badge
  const renderSeverityBadge = (severity) => {
    if (!severity) return null;
    
    let classes = '';
    switch (severity) {
      case 'critical':
        classes = 'bg-red-100 text-red-800 rounded-full px-3 py-1 text-sm font-medium';
        break;
      case 'high':
        classes = 'bg-orange-100 text-orange-800 rounded-full px-3 py-1 text-sm font-medium';
        break;
      case 'medium':
        classes = 'bg-yellow-100 text-yellow-800 rounded-full px-3 py-1 text-sm font-medium';
        break;
      case 'low':
        classes = 'bg-green-100 text-green-800 rounded-full px-3 py-1 text-sm font-medium';
        break;
      default:
        classes = 'bg-gray-100 text-gray-800 rounded-full px-3 py-1 text-sm font-medium';
    }
    
    return <span className={classes}>{severity}</span>;
  };
  
  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-800 mb-6">Compliance Controls</h1>
      
      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow-md mb-6">
        <div className="flex flex-wrap gap-4">
          <div className="w-full md:w-64">
            <label className="block text-sm font-medium text-gray-700 mb-1">Search</label>
            <input
              type="text"
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              placeholder="Search by ID, name, or description"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          
          <div className="w-full md:w-40">
            <label className="block text-sm font-medium text-gray-700 mb-1">Category</label>
            <select
              value={categoryFilter}
              onChange={e => setCategoryFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Categories</option>
              {uniqueCategories.map(category => (
                <option key={category} value={category}>{category}</option>
              ))}
            </select>
          </div>
          
          <div className="w-full md:w-40">
            <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
            <select
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Statuses</option>
              <option value="PASS">PASS</option>
              <option value="FAIL">FAIL</option>
              <option value="ERROR">ERROR</option>
            </select>
          </div>
        </div>
      </div>
      
      {/* Controls Table */}
      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="controls-table">
            <thead>
              <tr>
                <th 
                  onClick={() => handleSort('controlId')}
                  className="cursor-pointer hover:bg-gray-200"
                >
                  Control ID
                  {sortBy === 'controlId' && (
                    <span className="ml-1">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                  )}
                </th>
                <th 
                  onClick={() => handleSort('name')}
                  className="cursor-pointer hover:bg-gray-200"
                >
                  Name
                  {sortBy === 'name' && (
                    <span className="ml-1">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                  )}
                </th>
                <th 
                  onClick={() => handleSort('category')}
                  className="cursor-pointer hover:bg-gray-200"
                >
                  Category
                  {sortBy === 'category' && (
                    <span className="ml-1">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                  )}
                </th>
                <th 
                  onClick={() => handleSort('severity')}
                  className="cursor-pointer hover:bg-gray-200"
                >
                  Severity
                  {sortBy === 'severity' && (
                    <span className="ml-1">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                  )}
                </th>
                <th 
                  onClick={() => handleSort('status')}
                  className="cursor-pointer hover:bg-gray-200"
                >
                  Status
                  {sortBy === 'status' && (
                    <span className="ml-1">{sortDirection === 'asc' ? '▲' : '▼'}</span>
                  )}
                </th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredControls.map(controlId => {
                const control = controls[controlId];
                const result = latestResults[controlId] || {};
                
                return (
                  <React.Fragment key={controlId}>
                    <tr 
                      className={selectedControl === controlId ? 'bg-blue-50' : ''}
                      onClick={() => handleSelectControl(controlId)}
                    >
                      <td className="font-medium">{controlId}</td>
                      <td>{control.name}</td>
                      <td>{control.category}</td>
                      <td>{renderSeverityBadge(control.severity)}</td>
                      <td>{renderStatusBadge(result.status)}</td>
                      <td>
                        {control.remediation_available && result.status === 'FAIL' && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleRemediate(controlId);
                            }}
                            disabled={loading}
                            className="bg-blue-600 hover:bg-blue-700 text-white py-1 px-3 rounded-md text-sm"
                          >
                            Remediate
                          </button>
                        )}
                      </td>
                    </tr>
                    
                    {/* Detail view when a control is selected */}
                    {selectedControl === controlId && (
                      <tr>
                        <td colSpan="6" className="bg-blue-50 p-4">
                          <div className="mb-4">
                            <h3 className="text-lg font-semibold mb-2">{control.name}</h3>
                            <p className="text-gray-700 mb-4">{control.description}</p>
                            
                            {result.status && (
                              <div className="mb-4">
                                <div className="font-medium text-gray-700">Status Message:</div>
                                <div className="text-gray-600">{result.message}</div>
                              </div>
                            )}
                            
                            {result.remediation && (
                              <div>
                                <div className="font-medium text-gray-700">Remediation:</div>
                                <div className="text-gray-600">{result.remediation}</div>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
              
              {filteredControls.length === 0 && (
                <tr>
                  <td colSpan="6" className="text-center py-8 text-gray-500">
                    No controls found matching your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ControlsPage; 