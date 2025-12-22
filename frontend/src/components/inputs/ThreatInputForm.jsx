import React, { useState } from 'react';
import { ingestionApi } from '../../api/ingestionApi';

const ThreatInputForm = () => {
  const [formData, setFormData] = useState({
    type: 'ip',
    value: '',
    continuous_monitoring: false
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const inputTypes = [
    { value: 'ip', label: 'IP Address', placeholder: 'e.g., 192.168.1.1' },
    { value: 'domain', label: 'Domain', placeholder: 'e.g., example.com' },
    { value: 'url', label: 'URL', placeholder: 'e.g., https://example.com/malicious' },
    { value: 'hash', label: 'Hash (MD5/SHA1/SHA256)', placeholder: 'e.g., a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3' }
  ];

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const validateInput = () => {
    if (!formData.value.trim()) {
      setError('Please enter a value');
      return false;
    }

    // Basic validation based on type
    switch (formData.type) {
      case 'ip':
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(formData.value)) {
          setError('Please enter a valid IP address');
          return false;
        }
        break;
      case 'domain':
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        if (!domainRegex.test(formData.value)) {
          setError('Please enter a valid domain name');
          return false;
        }
        break;
      case 'url':
        try {
          new URL(formData.value);
        } catch {
          setError('Please enter a valid URL');
          return false;
        }
        break;
      case 'hash':
        const hashRegex = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
        if (!hashRegex.test(formData.value)) {
          setError('Please enter a valid hash (MD5, SHA1, or SHA256)');
          return false;
        }
        break;
      default:
        break;
    }

    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');

    if (!validateInput()) {
      return;
    }

    setLoading(true);
    try {
      const response = await ingestionApi.submitSingleInput(formData);
      setMessage('Threat input submitted successfully!');
      setFormData(prev => ({ ...prev, value: '' })); // Clear value but keep type
    } catch (err) {
      setError(err.message || 'Failed to submit threat input');
    } finally {
      setLoading(false);
    }
  };

  const currentType = inputTypes.find(t => t.value === formData.type);

  return (
    <div className="glass-card">
      <div className="glass-card-header">
        <h3 className="glass-card-title">Submit Single Threat Input</h3>
      </div>
      <div className="glass-card-content">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="glass-label">Indicator Type</label>
            <select
              name="type"
              value={formData.type}
              onChange={handleInputChange}
              className="glass-select"
            >
              {inputTypes.map(type => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="glass-label">Value</label>
            <input
              type="text"
              name="value"
              value={formData.value}
              onChange={handleInputChange}
              placeholder={currentType?.placeholder}
              className="glass-input"
              required
            />
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              name="continuous_monitoring"
              checked={formData.continuous_monitoring}
              onChange={handleInputChange}
              className="mr-2"
            />
            <label className="text-sm opacity-80">
              Enable continuous monitoring
            </label>
          </div>

          {error && (
            <div className="glass-card p-3 border-red-500/20 bg-red-500/10">
              <p className="text-red-300 text-sm">{error}</p>
            </div>
          )}

          {message && (
            <div className="glass-card p-3 border-green-500/20 bg-green-500/10">
              <p className="text-green-300 text-sm">{message}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="glass-button primary w-full"
          >
            {loading ? 'Submitting...' : 'Submit Threat Input'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default ThreatInputForm;