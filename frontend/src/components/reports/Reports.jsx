import React, { useState } from 'react';
import api from '../../services/api';
import './Reports.css';

const Reports = () => {
  const [reportConfig, setReportConfig] = useState({
    report_type: 'iocs',
    format: 'json',
    date_from: '',
    date_to: ''
  });
  const [loading, setLoading] = useState(false);
  const [showErrorModal, setShowErrorModal] = useState(false);

  const handleChange = (e) => {
    setReportConfig({
      ...reportConfig,
      [e.target.name]: e.target.value
    });
  };

  const handleExport = async () => {
    setLoading(true);
    try {
      const response = await api.post('/reports/export', reportConfig, {
        responseType: 'blob'
      });
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${reportConfig.report_type}_report.${reportConfig.format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      setShowErrorModal(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-content">
      <div className="glass-card glass-fade-in">
        <div className="glass-card-header">
          <h1 className="glass-card-title">Reports</h1>
        </div>
      </div>

      <div className="glass-card glass-fade-in max-w-md">
        <div className="glass-card-header">
          <h2 className="glass-card-title">Export Report</h2>
        </div>
        <div className="glass-card-content">
          <div className="space-y-4">
            <div>
              <label className="glass-label">Report Type</label>
              <select
                name="report_type"
                value={reportConfig.report_type}
                onChange={handleChange}
                className="glass-select"
              >
                <option value="iocs">IOCs</option>
                <option value="alerts">Alerts</option>
                <option value="audit">Audit Logs</option>
              </select>
            </div>

            <div>
              <label className="glass-label">Format</label>
              <select
                name="format"
                value={reportConfig.format}
                onChange={handleChange}
                className="glass-select"
              >
                <option value="json">JSON</option>
                <option value="csv">CSV</option>
              </select>
            </div>

            <div>
              <label className="glass-label">Date From (optional)</label>
              <input
                type="date"
                name="date_from"
                value={reportConfig.date_from}
                onChange={handleChange}
                className="glass-input"
              />
            </div>

            <div>
              <label className="glass-label">Date To (optional)</label>
              <input
                type="date"
                name="date_to"
                value={reportConfig.date_to}
                onChange={handleChange}
                className="glass-input"
              />
            </div>

            <button
              onClick={handleExport}
              disabled={loading}
              className="glass-button primary w-full"
            >
              {loading ? 'Exporting...' : 'Export Report'}
            </button>
          </div>
        </div>
      </div>

      {showErrorModal && (
        <div className="modal-overlay" onClick={() => setShowErrorModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Error</h3>
            <p>Error exporting report</p>
            <button className="glass-button primary" onClick={() => setShowErrorModal(false)}>OK</button>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;