import React, { useState } from 'react';
import api from '../../services/api';

const Reports = () => {
  const [reportConfig, setReportConfig] = useState({
    report_type: 'iocs',
    format: 'json',
    date_from: '',
    date_to: ''
  });
  const [loading, setLoading] = useState(false);

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
      console.error('Error exporting report:', error);
      alert('Error exporting report');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6">
      <h1 className="text-3xl font-bold mb-6">Reports</h1>
      
      <div className="bg-white rounded-lg shadow-md p-6 max-w-md">
        <h2 className="text-xl font-semibold mb-4">Export Report</h2>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Report Type
            </label>
            <select
              name="report_type"
              value={reportConfig.report_type}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="iocs">IOCs</option>
              <option value="alerts">Alerts</option>
              <option value="audit">Audit Logs</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Format
            </label>
            <select
              name="format"
              value={reportConfig.format}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Date From (optional)
            </label>
            <input
              type="date"
              name="date_from"
              value={reportConfig.date_from}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Date To (optional)
            </label>
            <input
              type="date"
              name="date_to"
              value={reportConfig.date_to}
              onChange={handleChange}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <button
            onClick={handleExport}
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50"
          >
            {loading ? 'Exporting...' : 'Export Report'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default Reports;