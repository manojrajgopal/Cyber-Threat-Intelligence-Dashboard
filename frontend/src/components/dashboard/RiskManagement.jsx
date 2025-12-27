import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../../services/api';
import './RiskManagement.css';

const RiskManagement = () => {
  const [riskData, setRiskData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // all, critical, high, medium, low

  useEffect(() => {
    fetchRiskData();
  }, [filter]);

  const fetchRiskData = async () => {
    try {
      setLoading(true);
      const response = await api.get(`/risk?filter=${filter}`);
      setRiskData(response.data);
    } catch (error) {
      console.error('Error fetching risk data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (riskScore) => {
    if (riskScore >= 0.9) return 'critical';
    if (riskScore >= 0.7) return 'high';
    if (riskScore >= 0.4) return 'medium';
    return 'low';
  };

  const getRiskBadgeClass = (riskLevel) => {
    const baseClasses = 'px-2 py-1 rounded text-xs font-medium';
    switch (riskLevel) {
      case 'critical': return `${baseClasses} bg-red-500/20 text-red-300`;
      case 'high': return `${baseClasses} bg-orange-500/20 text-orange-300`;
      case 'medium': return `${baseClasses} bg-yellow-500/20 text-yellow-300`;
      case 'low': return `${baseClasses} bg-green-500/20 text-green-300`;
      default: return `${baseClasses} bg-gray-500/20 text-gray-300`;
    }
  };

  const formatRiskScore = (score) => {
    return `${(score * 100).toFixed(1)}%`;
  };

  if (loading) {
    return (
      <div className="risk-content">
        <div className="glass-card">
          <div className="glass-card-content text-center py-16">
            Loading risk data...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="risk-content">
      {/* Header */}
      <div className="glass-card">
        <div className="glass-card-header">
          <h1 className="glass-card-title">Risk Management</h1>
          <Link to="/dashboard" className="back-button">
            ← Back to Dashboard
          </Link>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="glass-card">
        <div className="glass-card-content">
          <div className="risk-summary-grid">
            <div className="risk-summary-item border-l-4">
              <div className="risk-summary-value text-red-400">
                {riskData?.summary?.critical || 0}
              </div>
              <div className="risk-summary-label">Critical Risk</div>
              <div className="risk-summary-sublabel">Risk Score ≥ 0.9</div>
            </div>
            
            <div className="risk-summary-item border-l-4">
              <div className="risk-summary-value text-orange-400">
                {riskData?.summary?.high || 0}
              </div>
              <div className="risk-summary-label">High Risk</div>
              <div className="risk-summary-sublabel">Risk Score 0.7-0.9</div>
            </div>
            
            <div className="risk-summary-item border-l-4">
              <div className="risk-summary-value text-yellow-400">
                {riskData?.summary?.medium || 0}
              </div>
              <div className="risk-summary-label">Medium Risk</div>
              <div className="risk-summary-sublabel">Risk Score 0.4-0.7</div>
            </div>
            
            <div className="risk-summary-item border-l-4">
              <div className="risk-summary-value text-green-400">
                {riskData?.summary?.low || 0}
              </div>
              <div className="risk-summary-label">Low Risk</div>
              <div className="risk-summary-sublabel">Risk Score &lt; 0.4</div>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="glass-card">
        <div className="glass-card-content">
          <div className="risk-filters">
            <button 
              className={`filter-button ${filter === 'all' ? 'active' : ''}`}
              onClick={() => setFilter('all')}
            >
              All Risks ({riskData?.summary?.total || 0})
            </button>
            <button 
              className={`filter-button ${filter === 'critical' ? 'active' : ''}`}
              onClick={() => setFilter('critical')}
            >
              Critical ({riskData?.summary?.critical || 0})
            </button>
            <button 
              className={`filter-button ${filter === 'high' ? 'active' : ''}`}
              onClick={() => setFilter('high')}
            >
              High ({riskData?.summary?.high || 0})
            </button>
            <button 
              className={`filter-button ${filter === 'medium' ? 'active' : ''}`}
              onClick={() => setFilter('medium')}
            >
              Medium ({riskData?.summary?.medium || 0})
            </button>
            <button 
              className={`filter-button ${filter === 'low' ? 'active' : ''}`}
              onClick={() => setFilter('low')}
            >
              Low ({riskData?.summary?.low || 0})
            </button>
          </div>
        </div>
      </div>

      {/* Risk List */}
      <div className="glass-card">
        <div className="glass-card-header">
          <h2 className="glass-card-title">
            {filter === 'all' ? 'All Risks' : `${filter.charAt(0).toUpperCase() + filter.slice(1)} Risks`}
          </h2>
        </div>
        <div className="glass-card-content">
          {riskData?.risks?.length > 0 ? (
            <div className="risk-list">
              {riskData.risks.map((risk) => {
                const riskLevel = getRiskColor(risk.risk_score);
                return (
                  <div key={risk.id} className="risk-item">
                    <div className="risk-item-header">
                      <div className="risk-item-main">
                        <h3 className="risk-item-title">{risk.value}</h3>
                        <div className="risk-item-meta">
                          <span className="risk-item-type">{risk.type.toUpperCase()}</span>
                          <span className="risk-item-score">
                            Score: {formatRiskScore(risk.risk_score)}
                          </span>
                        </div>
                      </div>
                      <span className={getRiskBadgeClass(riskLevel)}>
                        {riskLevel.toUpperCase()}
                      </span>
                    </div>
                    
                    <div className="risk-item-details">
                      <div className="risk-item-info">
                        <span className="risk-item-label">Source:</span>
                        <span className="risk-item-value">{risk.source || 'Unknown'}</span>
                      </div>
                      <div className="risk-item-info">
                        <span className="risk-item-label">First Seen:</span>
                        <span className="risk-item-value">
                          {new Date(risk.first_seen).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="risk-item-info">
                        <span className="risk-item-label">Last Seen:</span>
                        <span className="risk-item-value">
                          {new Date(risk.last_seen).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                    
                    <div className="risk-item-actions">
                      <Link to={`/iocs/${risk.id}`} className="action-button view">
                        View Details
                      </Link>
                      <button className="action-button investigate">
                        Investigate
                      </button>
                      <button className="action-button mitigate">
                        Mitigate
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="no-risks">
              <p>No risks found for the selected filter.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default RiskManagement;