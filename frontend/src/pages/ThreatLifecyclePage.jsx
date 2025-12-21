import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';

const ThreatLifecyclePage = () => {
  const [lifecycleData, setLifecycleData] = useState({
    threats: [],
    stats: null
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedState, setSelectedState] = useState('new');

  const states = [
    'new',
    'under_analysis',
    'confirmed_malicious',
    'false_positive',
    'mitigated'
  ];

  useEffect(() => {
    loadLifecycleData();
  }, [selectedState]);

  const loadLifecycleData = async () => {
    try {
      setLoading(true);

      // Load threats by state
      const threatsResponse = await api.get(`/lifecycle/states/${selectedState}`);
      setLifecycleData(prev => ({ ...prev, threats: threatsResponse.data }));

      // Load stats
      const statsResponse = await api.get('/lifecycle/stats');
      setLifecycleData(prev => ({ ...prev, stats: statsResponse.data }));

    } catch (err) {
      setError('Failed to load lifecycle data');
    } finally {
      setLoading(false);
    }
  };

  const handleStateTransition = async (threatInputId, iocId, newState) => {
    try {
      await api.post('/lifecycle/transition', {
        threat_input_id: threatInputId,
        ioc_id: iocId,
        new_state: newState
      });
      loadLifecycleData(); // Refresh data
    } catch (err) {
      const errorDetail = err.response?.data?.detail;
      const errorMessage = typeof errorDetail === 'string' ? errorDetail : JSON.stringify(errorDetail) || err.message;
      alert('Failed to transition state: ' + errorMessage);
    }
  };

  const getStateColor = (state) => {
    const colors = {
      'new': 'bg-blue-100 text-blue-800',
      'under_analysis': 'bg-yellow-100 text-yellow-800',
      'confirmed_malicious': 'bg-red-100 text-red-800',
      'false_positive': 'bg-green-100 text-green-800',
      'mitigated': 'bg-gray-100 text-gray-800'
    };
    return colors[state] || 'bg-gray-100 text-gray-800';
  };

  if (loading) {
    return <div className="p-6">Loading threat lifecycle data...</div>;
  }

  if (error) {
    return <div className="p-6 text-red-600">{error}</div>;
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Threat Lifecycle Management</h1>
        <p className="text-gray-600 mt-2">
          Track and manage the lifecycle of threats from detection to resolution
        </p>
      </div>

      {/* Stats Overview */}
      {lifecycleData.stats && (
        <div className="mb-6 bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Lifecycle Statistics</h2>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {states.map(state => (
              <div key={state} className="text-center">
                <div className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${getStateColor(state)}`}>
                  {state.replace('_', ' ')}
                </div>
                <div className="text-2xl font-bold mt-2">
                  {lifecycleData.stats.state_counts?.[state] || 0}
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 text-sm text-gray-600">
            Total lifecycle entries: {lifecycleData.stats.total_lifecycle_entries || 0}
            {lifecycleData.stats.avg_time_under_analysis_hours && (
              <span className="ml-4">
                Avg time under analysis: {lifecycleData.stats.avg_time_under_analysis_hours.toFixed(1)} hours
              </span>
            )}
          </div>
        </div>
      )}

      {/* State Filter */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Filter by State
        </label>
        <select
          value={selectedState}
          onChange={(e) => setSelectedState(e.target.value)}
          className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          {states.map(state => (
            <option key={state} value={state}>
              {state.replace('_', ' ').toUpperCase()}
            </option>
          ))}
        </select>
      </div>

      {/* Threats List */}
      <div className="bg-white shadow-md rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-xl font-semibold">
            Threats in "{selectedState.replace('_', ' ')}" State
          </h2>
        </div>

        <div className="overflow-x-auto">
          {lifecycleData.threats.length === 0 ? (
            <div className="p-6 text-center text-gray-500">
              No threats found in this state
            </div>
          ) : (
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Threat
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Updated
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {lifecycleData.threats.map((threat, index) => (
                  <tr key={index}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900">
                        {threat.ioc ? (
                          <Link to={`/iocs/${threat.ioc.id}`} className="text-blue-600 hover:underline">
                            {threat.ioc.value}
                          </Link>
                        ) : (
                          threat.threat_input?.value || 'N/A'
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getStateColor(threat.state)}`}>
                        {threat.state.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(threat.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        {threat.state === 'new' && (
                          <button
                            onClick={() => handleStateTransition(threat.threat_input?.id, threat.ioc?.id, 'under_analysis')}
                            className="text-blue-600 hover:text-blue-900"
                          >
                            Start Analysis
                          </button>
                        )}
                        {threat.state === 'under_analysis' && (
                          <>
                            <button
                              onClick={() => handleStateTransition(threat.threat_input?.id, threat.ioc?.id, 'confirmed_malicious')}
                              className="text-red-600 hover:text-red-900"
                            >
                              Confirm Malicious
                            </button>
                            <button
                              onClick={() => handleStateTransition(threat.threat_input?.id, threat.ioc?.id, 'false_positive')}
                              className="text-green-600 hover:text-green-900"
                            >
                              Mark False Positive
                            </button>
                          </>
                        )}
                        {(threat.state === 'confirmed_malicious' || threat.state === 'false_positive') && (
                          <button
                            onClick={() => handleStateTransition(threat.threat_input?.id, threat.ioc?.id, 'mitigated')}
                            className="text-gray-600 hover:text-gray-900"
                          >
                            Mark Mitigated
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};

export default ThreatLifecyclePage;