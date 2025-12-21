import React, { useState, useEffect } from 'react';
import api from '../../services/api';

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
      console.error('Error fetching metrics:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="flex justify-center items-center h-64">Loading...</div>;
  }

  return (
    <div className="p-6">
      <h1 className="text-3xl font-bold mb-6">Dashboard</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700">Total IOCs</h3>
          <p className="text-3xl font-bold text-blue-600">{metrics?.total_iocs || 0}</p>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700">High Risk IOCs</h3>
          <p className="text-3xl font-bold text-red-600">{metrics?.high_risk_iocs || 0}</p>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700">Active Alerts</h3>
          <p className="text-3xl font-bold text-orange-600">{metrics?.active_alerts || 0}</p>
        </div>
        
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h3 className="text-lg font-semibold text-gray-700">Acknowledged Alerts</h3>
          <p className="text-3xl font-bold text-green-600">{metrics?.acknowledged_alerts || 0}</p>
        </div>
      </div>
      
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-4">Recent Alerts</h2>
        {metrics?.recent_alerts?.length > 0 ? (
          <div className="space-y-2">
            {metrics.recent_alerts.map((alert) => (
              <div key={alert.id} className="flex justify-between items-center p-3 bg-gray-50 rounded">
                <div>
                  <p className="font-medium">{alert.message}</p>
                  <p className="text-sm text-gray-600">
                    IOC: {alert.ioc?.value} | Severity: {alert.severity}
                  </p>
                </div>
                <span className={`px-2 py-1 rounded text-xs ${
                  alert.severity === 'critical' ? 'bg-red-100 text-red-800' :
                  alert.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                  alert.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                  'bg-green-100 text-green-800'
                }`}>
                  {alert.severity}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500">No recent alerts</p>
        )}
      </div>
    </div>
  );
};

export default Dashboard;