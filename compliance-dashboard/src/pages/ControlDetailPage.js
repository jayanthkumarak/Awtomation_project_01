import React, { useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import { getControlDetails, remediateControl } from '../store/complianceSlice';

const ControlDetailPage = () => {
  const { controlId } = useParams();
  const navigate = useNavigate();
  const dispatch = useDispatch();
  
  const { controls, latestResults, loading, error } = useSelector(state => state.compliance);
  
  useEffect(() => {
    if (controlId) {
      dispatch(getControlDetails({ controlId }));
    }
  }, [dispatch, controlId]);
  
  // Get control details
  const control = controls[controlId] || {};
  const result = latestResults[controlId] || {};
  
  // Handle remediation
  const handleRemediate = () => {
    const confirmRemediation = window.confirm(
      'Are you sure you want to remediate this control? This will make changes to your AWS resources.'
    );
    
    if (confirmRemediation) {
      dispatch(remediateControl({ control_id: controlId }));
    }
  };
  
  // Handle going back
  const handleBack = () => {
    navigate('/controls');
  };
  
  // Render status badge
  const renderStatusBadge = (status) => {
    if (!status) return null;
    
    let classes = '';
    switch (status) {
      case 'PASS':
        classes = 'bg-green-100 text-green-800 rounded-full px-3 py-1 text-sm font-medium';
        break;
      case 'FAIL':
        classes = 'bg-red-100 text-red-800 rounded-full px-3 py-1 text-sm font-medium';
        break;
      case 'ERROR':
        classes = 'bg-yellow-100 text-yellow-800 rounded-full px-3 py-1 text-sm font-medium';
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
      <div className="mb-6">
        <button
          onClick={handleBack}
          className="inline-flex items-center text-sm text-blue-600 hover:text-blue-800"
        >
          <svg className="h-5 w-5 mr-1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M12.707 5.293a1 1 0 010 1.414L9.414 10l3.293 3.293a1 1 0 01-1.414 1.414l-4-4a1 1 0 010-1.414l4-4a1 1 0 011.414 0z" clipRule="evenodd" />
          </svg>
          Back to Controls
        </button>
      </div>
      
      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6">
          Error: {error}
        </div>
      )}
      
      {loading ? (
        <div className="text-center py-12">
          <svg className="animate-spin h-8 w-8 text-blue-500 mx-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <p className="mt-4 text-gray-600">Loading control details...</p>
        </div>
      ) : control && Object.keys(control).length > 0 ? (
        <div>
          <div className="bg-white rounded-lg shadow-md overflow-hidden">
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h1 className="text-2xl font-bold text-gray-800">{controlId}: {control.name}</h1>
                  <div className="mt-2 flex items-center space-x-2">
                    <div className="text-gray-500">Category: {control.category}</div>
                    <div>{renderSeverityBadge(control.severity)}</div>
                    {result.status && <div>{renderStatusBadge(result.status)}</div>}
                  </div>
                </div>
                
                {control.remediation_available && result.status === 'FAIL' && (
                  <button
                    onClick={handleRemediate}
                    disabled={loading}
                    className="bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-md text-sm font-medium"
                  >
                    Remediate
                  </button>
                )}
              </div>
              
              <div className="prose max-w-none">
                <h2 className="text-lg font-semibold text-gray-700 mt-6 mb-3">Description</h2>
                <p className="text-gray-600">{control.description}</p>
                
                <h2 className="text-lg font-semibold text-gray-700 mt-6 mb-3">Check Details</h2>
                <div className="bg-gray-50 p-4 rounded-lg">
                  <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-4">
                    <div>
                      <dt className="text-sm font-medium text-gray-500">Status</dt>
                      <dd className="mt-1 text-sm text-gray-900">{result.status || 'Not scanned'}</dd>
                    </div>
                    <div>
                      <dt className="text-sm font-medium text-gray-500">Last Checked</dt>
                      <dd className="mt-1 text-sm text-gray-900">
                        {result.timestamp ? new Date(result.timestamp).toLocaleString() : 'Never'}
                      </dd>
                    </div>
                    {result.resources && result.resources.length > 0 && (
                      <div className="col-span-2">
                        <dt className="text-sm font-medium text-gray-500">Affected Resources</dt>
                        <dd className="mt-1 text-sm text-gray-900">
                          <ul className="list-disc pl-5 space-y-1">
                            {result.resources.map((resource, index) => (
                              <li key={index}>{resource}</li>
                            ))}
                          </ul>
                        </dd>
                      </div>
                    )}
                  </dl>
                </div>
                
                {result.message && (
                  <>
                    <h2 className="text-lg font-semibold text-gray-700 mt-6 mb-3">Status Message</h2>
                    <div className="bg-gray-50 p-4 rounded-lg whitespace-pre-wrap font-mono text-sm">
                      {result.message}
                    </div>
                  </>
                )}
                
                {control.remediation && (
                  <>
                    <h2 className="text-lg font-semibold text-gray-700 mt-6 mb-3">Remediation</h2>
                    <p className="text-gray-600">{control.remediation}</p>
                    
                    {result.status === 'FAIL' && control.remediation_steps && (
                      <div className="mt-4">
                        <h3 className="text-md font-semibold text-gray-700 mb-2">Remediation Steps</h3>
                        <ol className="list-decimal pl-5 space-y-1 text-gray-600">
                          {control.remediation_steps.map((step, index) => (
                            <li key={index}>{step}</li>
                          ))}
                        </ol>
                      </div>
                    )}
                  </>
                )}
                
                {control.reference_links && control.reference_links.length > 0 && (
                  <>
                    <h2 className="text-lg font-semibold text-gray-700 mt-6 mb-3">References</h2>
                    <ul className="list-disc pl-5 space-y-1 text-gray-600">
                      {control.reference_links.map((link, index) => (
                        <li key={index}>
                          <a href={link.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                            {link.title || link.url}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow-md p-8 text-center">
          <svg className="h-12 w-12 text-gray-400 mx-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 className="mt-2 text-sm font-medium text-gray-900">Control not found</h3>
          <p className="mt-1 text-sm text-gray-500">
            The control with ID "{controlId}" was not found.
          </p>
          <div className="mt-6">
            <button
              onClick={handleBack}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              Go to Controls
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ControlDetailPage; 