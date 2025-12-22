import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import api from '../../services/api';


const AlertsTable = ({ api }) => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const tableRef = useRef(null);
  const rowsRef = useRef([]);

  useEffect(() => {
    fetchAlerts();
    // Simulate initial animation
    setTimeout(() => {
      animateTableRows();
    }, 300);
  }, []);

  const fetchAlerts = async () => {
    try {
      // Simulated API call - replace with actual API
      const mockAlerts = [
        {
          id: 1,
          ioc: { value: '192.168.1.100', type: 'IP Address' },
          severity: 'critical',
          message: 'Malicious activity detected from external source',
          acknowledged: false,
          created_at: '2025-12-20T10:30:00Z'
        },
        {
          id: 2,
          ioc: { value: 'malicious-domain.com', type: 'Domain' },
          severity: 'high',
          message: 'Phishing attempt detected',
          acknowledged: true,
          created_at: '2025-12-19T14:20:00Z'
        },
        {
          id: 3,
          ioc: { value: 'd4e5f6a7b8c9d0e1', type: 'File Hash' },
          severity: 'medium',
          message: 'Suspicious file download detected',
          acknowledged: false,
          created_at: '2025-12-21T09:15:00Z'
        },
        {
          id: 4,
          ioc: { value: 'https://evil-site.net/login', type: 'URL' },
          severity: 'low',
          message: 'Potential malware distribution site',
          acknowledged: false,
          created_at: '2025-12-21T11:45:00Z'
        },
        {
          id: 5,
          ioc: { value: '10.0.0.55', type: 'IP Address' },
          severity: 'high',
          message: 'Internal port scanning detected',
          acknowledged: true,
          created_at: '2025-12-18T16:40:00Z'
        }
      ];
      setAlerts(mockAlerts);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    } finally {
      setLoading(false);
      // Animate rows after data loads
      setTimeout(() => {
        animateTableRows();
      }, 100);
    }
  };

  const animateTableRows = () => {
    rowsRef.current.forEach((row, index) => {
      if (row) {
        // Reset for animation
        row.style.opacity = '0';
        row.style.transform = 'translateY(20px)';
        
        // Animate in with delay
        setTimeout(() => {
          row.style.transition = 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
          row.style.opacity = '1';
          row.style.transform = 'translateY(0)';
        }, index * 100);
      }
    });
  };

  const handleAcknowledge = async (alertId, acknowledged) => {
    try {
      // Simulate API call
      console.log(`Updating alert ${alertId} to acknowledged: ${acknowledged}`);
      
      // Update local state
      setAlerts(prev => prev.map(alert => 
        alert.id === alertId ? { ...alert, acknowledged } : alert
      ));
      
      // Animate the updated row
      const rowIndex = alerts.findIndex(a => a.id === alertId);
      if (rowIndex !== -1 && rowsRef.current[rowIndex]) {
        rowsRef.current[rowIndex].style.transform = 'scale(1.02)';
        setTimeout(() => {
          rowsRef.current[rowIndex].style.transform = 'scale(1)';
        }, 300);
      }
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    }
  };

  if (loading) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16">
          Loading Threat Intelligence...
        </div>
      </div>
    );
  }

  return (
    <div className="glass-content">
      <div className="glass-card">
        <div className="glass-card-header">
          <h1 className="glass-card-title">Alerts</h1>
          <div className="flex gap-4">
            <div className="glass-card p-2">
              <span className="text-sm opacity-70">Active: </span>
              <span className="font-medium text-red-300">{alerts.filter(a => !a.acknowledged).length}</span>
            </div>
            <div className="glass-card p-2">
              <span className="text-sm opacity-70">Total: </span>
              <span className="font-medium">{alerts.length}</span>
            </div>
          </div>
        </div>
        <div className="glass-card-content">
          <div className="glass-card overflow-hidden">
            <table className="glass-table w-full">
              <thead>
                <tr>
                  <th>IOC</th>
                  <th>Severity</th>
                  <th>Message</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <div>
                        <div className="font-medium">
                          <Link to={`/iocs/${alert.ioc?.id}`} className="hover:opacity-80">
                            {alert.ioc?.value}
                          </Link>
                        </div>
                        <div className="text-sm opacity-70">{alert.ioc?.type}</div>
                      </div>
                    </td>
                    <td>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        alert.severity === 'critical' ? 'bg-red-500/20 text-red-300' :
                        alert.severity === 'high' ? 'bg-orange-500/20 text-orange-300' :
                        alert.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-300' :
                        'bg-green-500/20 text-green-300'
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="max-w-xs truncate">{alert.message}</td>
                    <td>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        alert.acknowledged ? 'bg-green-500/20 text-green-300' : 'bg-red-500/20 text-red-300'
                      }`}>
                        {alert.acknowledged ? 'Acknowledged' : 'Active'}
                      </span>
                    </td>
                    <td className="opacity-70 text-sm">
                      {new Date(alert.created_at).toLocaleDateString()}
                    </td>
                    <td>
                      {!alert.acknowledged ? (
                        <button
                          onClick={() => handleAcknowledge(alert.id, true)}
                          className="glass-button primary text-xs px-2 py-1"
                        >
                          Acknowledge
                        </button>
                      ) : (
                        <button
                          onClick={() => handleAcknowledge(alert.id, false)}
                          className="glass-button secondary text-xs px-2 py-1"
                        >
                          Unacknowledge
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {alerts.length === 0 && (
            <div className="text-center py-8 opacity-70">
              No alerts found
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertsTable;