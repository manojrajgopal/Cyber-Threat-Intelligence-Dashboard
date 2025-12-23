import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';
import './AccountThreatsPage.css';

const AccountThreatsPage = () => {
  const [accountData, setAccountData] = useState({
    threats: null,
    stats: null
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadAccountData();
  }, []);

  const loadAccountData = async () => {
    try {
      setLoading(true);

      // Load account threats
      const threatsResponse = await api.get('/account/threats');
      setAccountData(prev => ({ ...prev, threats: threatsResponse.data }));

      // Load account stats
      const statsResponse = await api.get('/account/stats');
      setAccountData(prev => ({ ...prev, stats: statsResponse.data }));

    } catch (err) {
      setError('Failed to load account data');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveThreat = async (threatId, type) => {
    try {
      if (type === 'ioc') {
        await api.delete(`/account/threats/ioc/${threatId}`);
      } else {
        await api.delete(`/account/threats/input/${threatId}`);
      }
      loadAccountData(); // Refresh data
    } catch (err) {
      alert('Failed to remove threat: ' + err.response?.data?.detail || err.message);
    }
  };

  if (loading) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16">
          Loading account threats...
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
          <h1 className="glass-card-title">Account Threat Overview</h1>
          <Link
            to="/threat-lifecycle"
            className="glass-button primary"
          >
            Manage Lifecycle
          </Link>
        </div>
        <div className="glass-card-content">
          <p className="opacity-70">
            Threats assigned to your account with isolation and access control
          </p>
        </div>
      </div>

      {/* Account Statistics */}
      {accountData.stats && (
        <div className="glass-card glass-fade-in">
          <div className="glass-card-header">
            <h2 className="glass-card-title">Account Statistics</h2>
          </div>
          <div className="glass-card-content">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
              <div className="glass-card p-4 text-center">
                <div className="text-2xl font-bold text-blue-300">
                  {accountData.stats.total_threats || 0}
                </div>
                <div className="text-sm opacity-70">Total Threats</div>
              </div>
              <div className="glass-card p-4 text-center">
                <div className="text-2xl font-bold text-red-300">
                  {accountData.stats.ioc_count || 0}
                </div>
                <div className="text-sm opacity-70">IOCs</div>
              </div>
              <div className="glass-card p-4 text-center">
                <div className="text-2xl font-bold text-yellow-300">
                  {accountData.stats.threat_input_count || 0}
                </div>
                <div className="text-sm opacity-70">Threat Inputs</div>
              </div>
              <div className="glass-card p-4 text-center">
                <div className="text-2xl font-bold text-purple-300">
                  {accountData.stats.high_risk_count || 0}
                </div>
                <div className="text-sm opacity-70">High Risk</div>
              </div>
            </div>
            <div className="text-sm opacity-70">
              Average Risk Score: {(accountData.stats.avg_risk_score * 100 || 0).toFixed(1)}%
            </div>
          </div>
        </div>
      )}

      {/* IOCs Section */}
      {accountData.threats?.iocs && accountData.threats.iocs.length > 0 && (
        <div className="glass-card glass-fade-in">
          <div className="glass-card-header">
            <h2 className="glass-card-title">Assigned IOCs</h2>
          </div>
          <div className="glass-card-content">
            <div className="overflow-x-auto">
              <table className="glass-table w-full">
                <thead>
                  <tr>
                    <th>IOC</th>
                    <th>Type</th>
                    <th>Risk Score</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {accountData.threats.iocs.map((ioc, index) => (
                    <tr key={index}>
                      <td className="font-medium">{ioc.value}</td>
                      <td>
                        <span className="px-2 py-1 text-xs rounded-full bg-blue-500/20 text-blue-300">
                          {ioc.type}
                        </span>
                      </td>
                      <td className="opacity-70 text-sm">
                        {(ioc.risk_score * 100).toFixed(1)}%
                      </td>
                      <td className="opacity-70 text-sm">
                        {new Date(ioc.created_at).toLocaleDateString()}
                      </td>
                      <td>
                        <button
                          onClick={() => handleRemoveThreat(ioc.id, 'ioc')}
                          className="glass-button danger text-xs px-2 py-1"
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Threat Inputs Section */}
      {accountData.threats?.threat_inputs && accountData.threats.threat_inputs.length > 0 && (
        <div className="glass-card glass-fade-in">
          <div className="glass-card-header">
            <h2 className="glass-card-title">Assigned Threat Inputs</h2>
          </div>
          <div className="glass-card-content">
            <div className="overflow-x-auto">
              <table className="glass-table w-full">
                <thead>
                  <tr>
                    <th>Input</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {accountData.threats.threat_inputs.map((input, index) => (
                    <tr key={index}>
                      <td className="font-medium">{input.value}</td>
                      <td>
                        <span className="px-2 py-1 text-xs rounded-full bg-green-500/20 text-green-300">
                          {input.type}
                        </span>
                      </td>
                      <td>
                        <span className={`px-2 py-1 text-xs rounded-full ${
                          input.status === 'processed'
                            ? 'bg-green-500/20 text-green-300'
                            : 'bg-yellow-500/20 text-yellow-300'
                        }`}>
                          {input.status}
                        </span>
                      </td>
                      <td className="opacity-70 text-sm">
                        {new Date(input.created_at).toLocaleDateString()}
                      </td>
                      <td>
                        <button
                          onClick={() => handleRemoveThreat(input.id, 'threat_input')}
                          className="glass-button danger text-xs px-2 py-1"
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {(!accountData.threats?.iocs?.length && !accountData.threats?.threat_inputs?.length) && (
        <div className="glass-card glass-fade-in">
          <div className="glass-card-content text-center py-16">
            <div className="text-6xl mb-4">🛡️</div>
            <h3 className="text-lg font-medium mb-2">No Threats Assigned</h3>
            <p className="opacity-70">
              No threats are currently assigned to your account. Submit new threats through the Threat Input page.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default AccountThreatsPage;