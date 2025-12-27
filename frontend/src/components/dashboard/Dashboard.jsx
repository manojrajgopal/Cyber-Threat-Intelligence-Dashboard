import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../../services/api';
import './Dashboard.css';

const Dashboard = () => {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMetrics();
  }, []);

  const fetchMetrics = async () => {
    try {
      const response = await api.get('/dashboard/metrics');
      setMetrics(response.data);
    } catch (error) {
      // Error fetching metrics
    } finally {
      setLoading(false);
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
          <h1 className="glass-card-title">Dashboard Overview</h1>
        </div>
        <div className="glass-card-content">
          <div className="glass-metric-grid">
            <Link to="/iocs" className="glass-metric-item">
              <div className="glass-metric-value">{metrics?.total_iocs || 0}</div>
              <div className="glass-metric-label">Total IOCs</div>
            </Link>
            <Link to="/iocs" className="glass-metric-item">
              <div className="glass-metric-value">{metrics?.high_risk_iocs || 0}</div>
              <div className="glass-metric-label">High Risk IOCs</div>
            </Link>
            <Link to="/alerts" className="glass-metric-item">
              <div className="glass-metric-value">{metrics?.active_alerts || 0}</div>
              <div className="glass-metric-label">Active Alerts</div>
            </Link>
            <Link to="/alerts" className="glass-metric-item">
              <div className="glass-metric-value">{metrics?.acknowledged_alerts || 0}</div>
              <div className="glass-metric-label">Acknowledged Alerts</div>
            </Link>
          </div>
        </div>
      </div>

      <div className="glass-card">
        <div className="glass-card-header">
          <h2 className="glass-card-title">Recent Alerts</h2>
        </div>
        <div className="glass-card-content">
          {metrics?.recent_alerts?.length > 0 ? (
            <div className="space-y-2">
              {metrics.recent_alerts.map((alert) => (
                <div key={alert.id} className="glass-card p-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="font-medium">{alert.message}</p>
                      <p className="text-sm opacity-70">
                        IOC: <Link to={`/iocs/${alert.ioc?.id}`} className="hover:opacity-100 transition-opacity">{alert.ioc?.value}</Link> | Severity: {alert.severity}
                      </p>
                    </div>
                    <span className={`px-2 py-1 rounded text-xs ${
                      alert.severity === 'critical' ? 'bg-red-500/20 text-red-300' :
                      alert.severity === 'high' ? 'bg-orange-500/20 text-orange-300' :
                      alert.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-300' :
                      'bg-green-500/20 text-green-300'
                    }`}>
                      {alert.severity}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="opacity-70">No recent alerts</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;