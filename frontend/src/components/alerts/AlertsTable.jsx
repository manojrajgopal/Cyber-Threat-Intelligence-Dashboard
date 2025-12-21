import React, { useState, useEffect, useRef } from 'react';
import './AlertsTable.css';

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
      <div className="dashboard-container">
        <div className="glass-card loading-container">
          <div className="loading-animation">
            <div className="loading-spinner"></div>
            <p className="loading-text">Loading Threat Intelligence...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div className="header-content">
          <h1 className="dashboard-title">
            <span className="title-word">Threat</span>
            <span className="title-word">Intelligence</span>
            <span className="title-word">Alerts</span>
          </h1>
          <p className="dashboard-subtitle">Real-time monitoring and incident response</p>
        </div>
        <div className="header-stats">
          <div className="stat-badge">
            <span className="stat-label">Active</span>
            <span className="stat-value critical">{alerts.filter(a => !a.acknowledged).length}</span>
          </div>
          <div className="stat-badge">
            <span className="stat-label">Total</span>
            <span className="stat-value">{alerts.length}</span>
          </div>
        </div>
      </div>

      <div className="glass-card table-container" ref={tableRef}>
        <div className="table-header">
          <h2 className="table-title">Security Alerts Dashboard</h2>
          <div className="table-actions">
            <button className="action-btn refresh-btn" onClick={fetchAlerts}>
              <span className="btn-icon">↻</span>
              Refresh
            </button>
          </div>
        </div>

        <div className="table-wrapper">
          <table className="alerts-table">
            <thead>
              <tr>
                <th className="table-head-cell">
                  <div className="head-content">
                    <span className="head-icon">🔍</span>
                    Indicator of Compromise
                  </div>
                </th>
                <th className="table-head-cell">
                  <div className="head-content">
                    <span className="head-icon">⚠️</span>
                    Severity Level
                  </div>
                </th>
                <th className="table-head-cell">
                  <div className="head-content">
                    <span className="head-icon">📝</span>
                    Alert Description
                  </div>
                </th>
                <th className="table-head-cell">
                  <div className="head-content">
                    <span className="head-icon">📊</span>
                    Status
                  </div>
                </th>
                <th className="table-head-cell">
                  <div className="head-content">
                    <span className="head-icon">🕒</span>
                    Time Detected
                  </div>
                </th>
                <th className="table-head-cell">
                  <div className="head-content">
                    <span className="head-icon">⚡</span>
                    Actions
                  </div>
                </th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, index) => (
                <tr 
                  key={alert.id} 
                  className="table-row"
                  ref={el => rowsRef.current[index] = el}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.transform = 'translateX(5px)';
                    e.currentTarget.style.boxShadow = '0 8px 32px rgba(222, 158, 54, 0.2)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.transform = 'translateX(0)';
                    e.currentTarget.style.boxShadow = 'none';
                  }}
                >
                  <td className="table-cell">
                    <div className="ioc-cell">
                      <div className="ioc-value">{alert.ioc?.value}</div>
                      <div className="ioc-type">{alert.ioc?.type}</div>
                    </div>
                  </td>
                  <td className="table-cell">
                    <span className={`severity-badge ${alert.severity}`}>
                      <span className="severity-dot"></span>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="table-cell">
                    <div className="message-cell">{alert.message}</div>
                  </td>
                  <td className="table-cell">
                    <div className={`status-badge ${alert.acknowledged ? 'acknowledged' : 'active'}`}>
                      <span className="status-indicator"></span>
                      {alert.acknowledged ? 'Acknowledged' : 'Active'}
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="time-cell">
                      <div className="time-date">
                        {new Date(alert.created_at).toLocaleDateString()}
                      </div>
                      <div className="time-hour">
                        {new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </div>
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="action-cell">
                      {!alert.acknowledged ? (
                        <button
                          onClick={() => handleAcknowledge(alert.id, true)}
                          className="action-button acknowledge-btn"
                        >
                          <span className="action-icon">✓</span>
                          Acknowledge
                        </button>
                      ) : (
                        <button
                          onClick={() => handleAcknowledge(alert.id, false)}
                          className="action-button unacknowledge-btn"
                        >
                          <span className="action-icon">↺</span>
                          Re-activate
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {alerts.length === 0 && (
          <div className="empty-state">
            <div className="empty-icon">🎯</div>
            <h3 className="empty-title">No Active Threats Detected</h3>
            <p className="empty-subtitle">All systems are secure. Monitor this space for real-time alerts.</p>
          </div>
        )}
      </div>

      <div className="dashboard-footer">
        <div className="footer-stats">
          <div className="footer-stat">
            <span className="footer-stat-label">Critical Threats</span>
            <span className="footer-stat-value accent">
              {alerts.filter(a => a.severity === 'critical').length}
            </span>
          </div>
          <div className="footer-stat">
            <span className="footer-stat-label">Response Time</span>
            <span className="footer-stat-value">2.4s</span>
          </div>
          <div className="footer-stat">
            <span className="footer-stat-label">Last Updated</span>
            <span className="footer-stat-value">
              {new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlertsTable;