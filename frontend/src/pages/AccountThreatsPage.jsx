import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../services/api';

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
    return <div className="p-6">Loading account threats...</div>;
  }

  if (error) {
    return <div className="p-6 text-red-600">{error}</div>;
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Account Threat Overview</h1>
            <p className="text-gray-600 mt-2">
              Threats assigned to your account with isolation and access control
            </p>
          </div>
          <Link
            to="/threat-lifecycle"
            className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
          >
            Manage Lifecycle
          </Link>
        </div>
      </div>

      {/* Account Statistics */}
      {accountData.stats && (
        <div className="mb-6 bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Account Statistics</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-blue-50 p-4 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">
                {accountData.stats.total_threats || 0}
              </div>
              <div className="text-sm text-blue-800">Total Threats</div>
            </div>
            <div className="bg-red-50 p-4 rounded-lg">
              <div className="text-2xl font-bold text-red-600">
                {accountData.stats.ioc_count || 0}
              </div>
              <div className="text-sm text-red-800">IOCs</div>
            </div>
            <div className="bg-yellow-50 p-4 rounded-lg">
              <div className="text-2xl font-bold text-yellow-600">
                {accountData.stats.threat_input_count || 0}
              </div>
              <div className="text-sm text-yellow-800">Threat Inputs</div>
            </div>
            <div className="bg-purple-50 p-4 rounded-lg">
              <div className="text-2xl font-bold text-purple-600">
                {accountData.stats.high_risk_count || 0}
              </div>
              <div className="text-sm text-purple-800">High Risk</div>
            </div>
          </div>
          <div className="mt-4 text-sm text-gray-600">
            Average Risk Score: {(accountData.stats.avg_risk_score * 100 || 0).toFixed(1)}%
          </div>
        </div>
      )}

      {/* IOCs Section */}
      {accountData.threats?.iocs && accountData.threats.iocs.length > 0 && (
        <div className="mb-6">
          <h2 className="text-xl font-semibold mb-4">Assigned IOCs</h2>
          <div className="bg-white shadow-md rounded-lg overflow-hidden">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    IOC
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Risk Score
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Created
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {accountData.threats.iocs.map((ioc, index) => (
                  <tr key={index}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {ioc.value}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {(ioc.risk_score * 100).toFixed(1)}%
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(ioc.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <button
                        onClick={() => handleRemoveThreat(ioc.id, 'ioc')}
                        className="text-red-600 hover:text-red-900"
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
      )}

      {/* Threat Inputs Section */}
      {accountData.threats?.threat_inputs && accountData.threats.threat_inputs.length > 0 && (
        <div className="mb-6">
          <h2 className="text-xl font-semibold mb-4">Assigned Threat Inputs</h2>
          <div className="bg-white shadow-md rounded-lg overflow-hidden">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Input
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Created
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {accountData.threats.threat_inputs.map((input, index) => (
                  <tr key={index}>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {input.value}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
                        {input.type}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                        input.status === 'processed'
                          ? 'bg-green-100 text-green-800'
                          : 'bg-yellow-100 text-yellow-800'
                      }`}>
                        {input.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(input.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <button
                        onClick={() => handleRemoveThreat(input.id, 'threat_input')}
                        className="text-red-600 hover:text-red-900"
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
      )}

      {/* Empty State */}
      {(!accountData.threats?.iocs?.length && !accountData.threats?.threat_inputs?.length) && (
        <div className="bg-white p-12 rounded-lg shadow-md text-center">
          <div className="text-gray-400 text-6xl mb-4">🛡️</div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No Threats Assigned</h3>
          <p className="text-gray-600">
            No threats are currently assigned to your account. Submit new threats through the Threat Input page.
          </p>
        </div>
      )}
    </div>
  );
};

export default AccountThreatsPage;