import React, { useState } from 'react';
import { ingestionApi } from '../../api/ingestionApi';
import './BulkUpload.css';

const BulkUpload = () => {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [jobId, setJobId] = useState(null);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      // Validate file type
      const allowedTypes = ['text/csv', 'application/json'];
      const allowedExtensions = ['.csv', '.json'];

      const fileExtension = selectedFile.name.toLowerCase().substring(selectedFile.name.lastIndexOf('.'));

      if (!allowedTypes.includes(selectedFile.type) && !allowedExtensions.includes(fileExtension)) {
        setError('Please select a CSV or JSON file');
        setFile(null);
        return;
      }

      // Validate file size (max 10MB)
      if (selectedFile.size > 10 * 1024 * 1024) {
        setError('File size must be less than 10MB');
        setFile(null);
        return;
      }

      setFile(selectedFile);
      setError('');
      setMessage('');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file');
      return;
    }

    setLoading(true);
    setError('');
    setMessage('');

    try {
      const response = await ingestionApi.uploadFile(file);
      setMessage('File uploaded successfully! Processing in background.');
      setJobId(response.data?.job_id);
      setFile(null);
      // Reset file input
      const fileInput = document.getElementById('file-input');
      if (fileInput) fileInput.value = '';
    } catch (err) {
      setError(err.message || 'Failed to upload file');
    } finally {
      setLoading(false);
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="glass-card">
      <div className="glass-card-header">
        <h3 className="glass-card-title">Bulk Upload Threat Indicators</h3>
      </div>
      <div className="glass-card-content">
        <p className="text-sm opacity-70 mb-4">
          Upload a CSV or JSON file containing multiple threat indicators.
          CSV should have columns: type, value. JSON should be an array of objects with type and value fields.
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="glass-label">Select File</label>
            <input
              id="file-input"
              type="file"
              accept=".csv,.json"
              onChange={handleFileChange}
              className="glass-input"
              required
            />
            {file && (
              <div className="mt-2 text-sm opacity-70">
                <strong>Selected:</strong> {file.name} ({formatFileSize(file.size)})
              </div>
            )}
          </div>

          {error && (
            <div className="glass-card p-3 border-red-500/20 bg-red-500/10">
              <p className="text-red-300 text-sm">{error}</p>
            </div>
          )}

          {message && (
            <div className="glass-card p-3 border-green-500/20 bg-green-500/10">
              <p className="text-green-300 text-sm">
                {message}
                {jobId && (
                  <div className="mt-2">
                    <strong>Job ID:</strong> {jobId}
                  </div>
                )}
              </p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !file}
            className="glass-button primary w-full"
          >
            {loading ? 'Uploading...' : 'Upload and Process'}
          </button>
        </form>

        <div className="mt-6">
          <h4 className="text-md font-medium mb-2 opacity-80">File Format Examples</h4>
          <div className="space-y-2 text-sm opacity-70">
            <div>
              <strong>CSV Format:</strong>
              <pre className="glass-card p-2 mt-1 text-xs">
{`type,value
ip,192.168.1.1
domain,malicious.com
url,https://bad.example.com`}
              </pre>
            </div>
            <div>
              <strong>JSON Format:</strong>
              <pre className="glass-card p-2 mt-1 text-xs">
{`[
  {"type": "ip", "value": "192.168.1.1"},
  {"type": "domain", "value": "malicious.com"},
  {"type": "url", "value": "https://bad.example.com"}
]`}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BulkUpload;