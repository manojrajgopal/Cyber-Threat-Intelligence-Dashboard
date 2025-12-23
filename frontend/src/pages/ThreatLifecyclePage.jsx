import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import './ThreatLifecyclePage.css';

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
      'new': 'bg-blue-500/20 text-blue-300',
      'under_analysis': 'bg-yellow-500/20 text-yellow-300',
      'confirmed_malicious': 'bg-red-500/20 text-red-300',
      'false_positive': 'bg-green-500/20 text-green-300',
      'mitigated': 'bg-gray-500/20 text-gray-300'
    };
    return colors[state] || 'bg-gray-500/20 text-gray-300';
  };

  if (loading) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16">
          Loading threat lifecycle data...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16 text-red-300">
          {error}
        </div>
      </div>
    );
  }

  return (
    <div className="glass-content">
      <div className="glass-card glass-fade-in">
        <div className="glass-card-header">
          <h1 className="glass-card-title">Threat Lifecycle Management</h1>
        </div>
        <div className="glass-card-content">
          <p className="opacity-70">
            Track and manage the lifecycle of threats from detection to resolution
          </p>
        </div>
      </div>

      {/* Stats Overview */}
      {lifecycleData.stats && (
        <div className="glass-card glass-fade-in">
          <div className="glass-card-header">
            <h2 className="glass-card-title">Lifecycle Statistics</h2>
          </div>
          <div className="glass-card-content">
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
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
            <div className="text-sm opacity-70">
              Total lifecycle entries: {lifecycleData.stats.total_lifecycle_entries || 0}
              {lifecycleData.stats.avg_time_under_analysis_hours && (
                <span className="ml-4">
                  Avg time under analysis: {lifecycleData.stats.avg_time_under_analysis_hours.toFixed(1)} hours
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* State Filter */}
      <div className="glass-card glass-fade-in">
        <div className="glass-card-content">
          <label className="glass-label">Filter by State</label>
          <select
            value={selectedState}
            onChange={(e) => setSelectedState(e.target.value)}
            className="glass-select"
          >
            {states.map(state => (
              <option key={state} value={state}>
                {state.replace('_', ' ').toUpperCase()}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Threats List */}
      <div className="glass-card glass-fade-in">
        <div className="glass-card-header">
          <h2 className="glass-card-title">
            Threats in "{selectedState.replace('_', ' ')}" State
          </h2>
        </div>
        <div className="glass-card-content">
          <div className="overflow-x-auto">
            {lifecycleData.threats.length === 0 ? (
              <div className="text-center py-8 opacity-70">
                No threats found in this state
              </div>
            ) : (
              <table className="glass-table w-full">
                <thead>
                  <tr>
                    <th>Threat</th>
                    <th>Type</th>
                    <th>Last Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {lifecycleData.threats.map((threat, index) => (
                    <tr key={index}>
                      <td>
                        <div className="font-medium">
                          {threat.ioc ? (
                            <Link to={`/iocs/${threat.ioc.id}`} className="hover:opacity-80">
                              {threat.ioc.value}
                            </Link>
                          ) : (
                            threat.threat_input?.value || 'N/A'
                          )}
                        </div>
                      </td>
                      <td>
                        <span className={`px-2 py-1 text-xs rounded-full ${getStateColor(threat.state)}`}>
                          {threat.state.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="opacity-70 text-sm">
                        {new Date(threat.timestamp).toLocaleString()}
                      </td>
                      <td>
                        <div className="flex flex-wrap gap-2">
                          {threat.state === 'new' && (
                            <button
                              onClick={() => handleStateTransition(threat.threat_input?.id, threat.ioc?.id, 'under_analysis')}
                              className="glass-button primary text-xs px-2 py-1"
                            >
                              Start Analysis
                            </button>
                          )}
                          {threat.state === 'under_analysis' && (
                            <>
                              <button
                                onClick={() => handleStateTransition(threat.threat_input?.id, threat.ioc?.id, 'confirmed_malicious')}
                                className="glass-button danger text-xs px-2 py-1"
                              >
                                Confirm Malicious
                              </button>
                              <button
                                onClick={() => handleStateTransition(threat.threat_input?.id, threat.ioc?.id, 'false_positive')}
                                className="glass-button secondary text-xs px-2 py-1"
                              >
                                Mark False Positive
                              </button>
                            </>
                          )}
                          {(threat.state === 'confirmed_malicious' || threat.state === 'false_positive') && (
                            <button
                              onClick={() => handleStateTransition(threat.threat_input?.id, threat.ioc?.id, 'mitigated')}
                              className="glass-button secondary text-xs px-2 py-1"
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
    </div>
  );
};

export default ThreatLifecyclePage;