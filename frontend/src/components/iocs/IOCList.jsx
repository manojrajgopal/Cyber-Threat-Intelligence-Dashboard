import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../../services/api';
import './IOCList.css';

const IOCList = () => {
  const [iocs, setIocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState('');

  useEffect(() => {
    fetchIOCs();
  }, [typeFilter]);

  const fetchIOCs = async () => {
    try {
      const params = typeFilter ? { type_filter: typeFilter } : {};
      const response = await api.get('/iocs', { params });
      setIocs(response.data);
    } catch (error) {
      console.error('Error fetching IOCs:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleEnrich = async (iocId) => {
    try {
      await api.post(`/iocs/${iocId}/enrich`);
      // Refresh the list to show updated enrichment status
      fetchIOCs();
    } catch (error) {
      console.error('Error enriching IOC:', error);
    }
  };

  if (loading) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16">
          Loading...
        </div>
      </div>
    );
  }

  return (
    <div className="glass-content">
      <div className="glass-card">
        <div className="glass-card-header">
          <h1 className="glass-card-title">IOCs</h1>
          <div className="flex space-x-4">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="glass-select"
            >
              <option value="">All Types</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash">Hash</option>
            </select>
          </div>
        </div>
        <div className="glass-card-content">
          <div className="glass-card overflow-hidden">
            <table className="glass-table w-full">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Risk Score</th>
                  <th>Source</th>
                  <th>Enriched</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc) => (
                  <tr key={ioc.id}>
                    <td>
                      <span className="px-2 py-1 text-xs rounded-full bg-blue-500/20 text-blue-300">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="font-medium">{ioc.value}</td>
                    <td>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        ioc.risk_score >= 0.7 ? 'bg-red-500/20 text-red-300' :
                        ioc.risk_score >= 0.4 ? 'bg-yellow-500/20 text-yellow-300' :
                        'bg-green-500/20 text-green-300'
                      }`}>
                        {(ioc.risk_score * 100).toFixed(0)}%
                      </span>
                    </td>
                    <td className="opacity-70">{ioc.source}</td>
                    <td>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        ioc.enriched ? 'bg-green-500/20 text-green-300' : 'bg-gray-500/20 text-gray-300'
                      }`}>
                        {ioc.enriched ? 'Yes' : 'No'}
                      </span>
                    </td>
                    <td className="space-x-2">
                      <Link
                        to={`/iocs/${ioc.id}`}
                        className="glass-button secondary text-xs px-2 py-1"
                      >
                        View
                      </Link>
                      <Link
                        to={`/iocs/${ioc.id}/intelligence`}
                        className="glass-button secondary text-xs px-2 py-1"
                      >
                        Intelligence
                      </Link>
                      {!ioc.enriched && (
                        <button
                          onClick={() => handleEnrich(ioc.id)}
                          className="glass-button primary text-xs px-2 py-1"
                        >
                          Enrich
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {iocs.length === 0 && (
            <div className="text-center py-8 opacity-70">
              No IOCs found
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default IOCList;