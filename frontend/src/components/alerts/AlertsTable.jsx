import React, { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import api from '../../services/api';


const AlertsTable = () => {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null); // id of alert being acted upon
  const [error, setError] = useState(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [createForm, setCreateForm] = useState({
    ioc_id: '',
    severity: 'medium',
    message: ''
  });
  const [iocs, setIocs] = useState([]);
  const [showViewModal, setShowViewModal] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [showFilterModal, setShowFilterModal] = useState(false);
  const [filters, setFilters] = useState({
    acknowledged: '',
    severity: '',
    sortBy: 'created_at',
    sortOrder: 'desc'
  });
  const tableRef = useRef(null);
  const rowsRef = useRef([]);

  useEffect(() => {
    fetchAlerts();
    fetchIocs();
    // Simulate initial animation
    setTimeout(() => {
      animateTableRows();
    }, 300);
  }, []);

  const fetchAlerts = async () => {
    try {
      setError(null);
      const params = new URLSearchParams();
      if (filters.acknowledged !== '') params.append('acknowledged', filters.acknowledged);
      if (filters.severity !== '') params.append('severity', filters.severity);
      params.append('sort_by', filters.sortBy);
      params.append('sort_order', filters.sortOrder);
      const response = await api.get(`/alerts/?${params}`);
      setAlerts(response.data);
    } catch (error) {
      console.error('Error fetching alerts:', error);
      setError('Failed to fetch alerts');
    } finally {
      setLoading(false);
      // Animate rows after data loads
      setTimeout(() => {
        animateTableRows();
      }, 100);
    }
  };

  const fetchIocs = async () => {
    try {
      const response = await api.get('/iocs');
      setIocs(response.data);
    } catch (error) {
      console.error('Error fetching IOCs:', error);
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
    setActionLoading(alertId);
    try {
      await api.put(`/alerts/${alertId}/acknowledge`, { acknowledged });

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
      setError('Failed to acknowledge alert');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDelete = async (alertId) => {
    if (!window.confirm('Are you sure you want to delete this alert?')) return;

    setActionLoading(alertId);
    try {
      await api.delete(`/alerts/${alertId}`);
      setAlerts(prev => prev.filter(alert => alert.id !== alertId));
    } catch (error) {
      console.error('Error deleting alert:', error);
      setError('Failed to delete alert');
    } finally {
      setActionLoading(null);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    setActionLoading('create');
    try {
      const formData = {
        ...createForm,
        ioc_id: parseInt(createForm.ioc_id)
      };
      const response = await api.post('/alerts', formData);
      setAlerts(prev => [response.data, ...prev]);
      setCreateForm({ ioc_id: '', severity: 'medium', message: '' });
      setShowCreateForm(false);
    } catch (error) {
      console.error('Error creating alert:', error);
      setError('Failed to create alert');
    } finally {
      setActionLoading(null);
    }
  };

  const handleView = (alert) => {
    setSelectedAlert(alert);
    setShowViewModal(true);
  };

  const handleFilter = () => {
    setShowFilterModal(true);
  };

  const applyFilters = () => {
    fetchAlerts();
    setShowFilterModal(false);
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
          <div className="flex justify-between items-center">
            <h1 className="glass-card-title">Alerts</h1>
            <div className="flex gap-2">
              <button
                onClick={handleFilter}
                className="glass-button secondary"
              >
                Filter
              </button>
              <button
                onClick={() => setShowCreateForm(!showCreateForm)}
                className="glass-button primary"
              >
                {showCreateForm ? 'Cancel' : 'Create Alert'}
              </button>
            </div>
          </div>
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

        {showCreateForm && (
          <div className="glass-card-content">
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">IOC</label>
                  <select
                    value={createForm.ioc_id}
                    onChange={(e) => setCreateForm(prev => ({ ...prev, ioc_id: e.target.value }))}
                    className="glass-input w-full"
                    required
                  >
                    <option value="">Select IOC</option>
                    {iocs.map(ioc => (
                      <option key={ioc.id} value={ioc.id}>
                        {ioc.value} ({ioc.type})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Severity</label>
                  <select
                    value={createForm.severity}
                    onChange={(e) => setCreateForm(prev => ({ ...prev, severity: e.target.value }))}
                    className="glass-input w-full"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Message</label>
                  <input
                    type="text"
                    value={createForm.message}
                    onChange={(e) => setCreateForm(prev => ({ ...prev, message: e.target.value }))}
                    className="glass-input w-full"
                    placeholder="Alert message"
                  />
                </div>
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={actionLoading === 'create'}
                  className="glass-button primary"
                >
                  {actionLoading === 'create' ? 'Creating...' : 'Create Alert'}
                </button>
              </div>
            </form>
          </div>
        )}

        <div className="glass-card-content">
          {error && (
            <div className="mb-4 p-3 bg-red-500/20 border border-red-500/30 rounded text-red-300">
              {error}
              <button
                onClick={() => setError(null)}
                className="ml-2 text-red-300 hover:text-red-100"
              >
                ×
              </button>
            </div>
          )}
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
                      <div className="flex gap-1">
                        <button
                          onClick={() => handleView(alert)}
                          className="glass-button secondary text-xs px-2 py-1"
                        >
                          View
                        </button>
                        {!alert.acknowledged ? (
                          <button
                            onClick={() => handleAcknowledge(alert.id, true)}
                            disabled={actionLoading === alert.id}
                            className="glass-button primary text-xs px-2 py-1"
                          >
                            {actionLoading === alert.id ? '...' : 'Acknowledge'}
                          </button>
                        ) : (
                          <button
                            onClick={() => handleAcknowledge(alert.id, false)}
                            disabled={actionLoading === alert.id}
                            className="glass-button secondary text-xs px-2 py-1"
                          >
                            {actionLoading === alert.id ? '...' : 'Unacknowledge'}
                          </button>
                        )}
                        <button
                          onClick={() => handleDelete(alert.id)}
                          disabled={actionLoading === alert.id}
                          className="glass-button danger text-xs px-2 py-1"
                        >
                          {actionLoading === alert.id ? '...' : 'Delete'}
                        </button>
                      </div>
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

      {/* View Modal */}
      {showViewModal && selectedAlert && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="glass-card max-w-2xl w-full mx-4">
            <div className="glass-card-header">
              <h2 className="glass-card-title">Alert Details</h2>
              <button
                onClick={() => setShowViewModal(false)}
                className="text-gray-400 hover:text-white"
              >
                ×
              </button>
            </div>
            <div className="glass-card-content space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">IOC</label>
                  <div className="glass-input w-full bg-gray-700">
                    {selectedAlert.ioc?.value} ({selectedAlert.ioc?.type})
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Severity</label>
                  <div className="glass-input w-full bg-gray-700">
                    {selectedAlert.severity}
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Status</label>
                  <div className="glass-input w-full bg-gray-700">
                    {selectedAlert.acknowledged ? 'Acknowledged' : 'Active'}
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Created At</label>
                  <div className="glass-input w-full bg-gray-700">
                    {new Date(selectedAlert.created_at).toLocaleString()}
                  </div>
                </div>
                {selectedAlert.acknowledged_at && (
                  <div>
                    <label className="block text-sm font-medium mb-1">Acknowledged At</label>
                    <div className="glass-input w-full bg-gray-700">
                      {new Date(selectedAlert.acknowledged_at).toLocaleString()}
                    </div>
                  </div>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Message</label>
                <div className="glass-input w-full bg-gray-700 min-h-20">
                  {selectedAlert.message || 'No message'}
                </div>
              </div>
              <div className="flex justify-end gap-2">
                {!selectedAlert.acknowledged ? (
                  <button
                    onClick={() => {
                      handleAcknowledge(selectedAlert.id, true);
                      setShowViewModal(false);
                    }}
                    disabled={actionLoading === selectedAlert.id}
                    className="glass-button primary"
                  >
                    {actionLoading === selectedAlert.id ? '...' : 'Acknowledge'}
                  </button>
                ) : (
                  <button
                    onClick={() => {
                      handleAcknowledge(selectedAlert.id, false);
                      setShowViewModal(false);
                    }}
                    disabled={actionLoading === selectedAlert.id}
                    className="glass-button secondary"
                  >
                    {actionLoading === selectedAlert.id ? '...' : 'Unacknowledge'}
                  </button>
                )}
                <button
                  onClick={() => setShowViewModal(false)}
                  className="glass-button secondary"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filter Modal */}
      {showFilterModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="glass-card max-w-md w-full mx-4">
            <div className="glass-card-header">
              <h2 className="glass-card-title">Filter & Sort Alerts</h2>
              <button
                onClick={() => setShowFilterModal(false)}
                className="text-gray-400 hover:text-white"
              >
                ×
              </button>
            </div>
            <div className="glass-card-content space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Status</label>
                <select
                  value={filters.acknowledged}
                  onChange={(e) => setFilters(prev => ({ ...prev, acknowledged: e.target.value }))}
                  className="glass-input w-full"
                >
                  <option value="">All</option>
                  <option value="true">Acknowledged</option>
                  <option value="false">Active</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select
                  value={filters.severity}
                  onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
                  className="glass-input w-full"
                >
                  <option value="">All</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Sort By</label>
                <select
                  value={filters.sortBy}
                  onChange={(e) => setFilters(prev => ({ ...prev, sortBy: e.target.value }))}
                  className="glass-input w-full"
                >
                  <option value="created_at">Created Date</option>
                  <option value="severity">Severity</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Sort Order</label>
                <select
                  value={filters.sortOrder}
                  onChange={(e) => setFilters(prev => ({ ...prev, sortOrder: e.target.value }))}
                  className="glass-input w-full"
                >
                  <option value="asc">Ascending</option>
                  <option value="desc">Descending</option>
                </select>
              </div>
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => {
                    setFilters({ acknowledged: '', severity: '', sortBy: 'created_at', sortOrder: 'desc' });
                  }}
                  className="glass-button secondary"
                >
                  Reset
                </button>
                <button
                  onClick={applyFilters}
                  className="glass-button primary"
                >
                  Apply Filters
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlertsTable;