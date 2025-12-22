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
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h3 className="text-lg font-semibold mb-4">Submit Single Threat Input</h3>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Indicator Type
          </label>
          <select
            name="type"
            value={formData.type}
            onChange={handleInputChange}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {inputTypes.map(type => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Value
          </label>
          <input
            type="text"
            name="value"
            value={formData.value}
            onChange={handleInputChange}
            placeholder={currentType?.placeholder}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>

        <div className="flex items-center">
          <input
            type="checkbox"
            name="continuous_monitoring"
            checked={formData.continuous_monitoring}
            onChange={handleInputChange}
            className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
          />
          <label className="ml-2 block text-sm text-gray-700">
            Enable continuous monitoring
          </label>
        </div>

        {error && (
          <div className="text-red-600 text-sm bg-red-50 p-3 rounded-md">
            {error}
          </div>
        )}

        {message && (
          <div className="text-green-600 text-sm bg-green-50 p-3 rounded-md">
            {message}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
        >
          {loading ? 'Submitting...' : 'Submit Threat Input'}
        </button>
      </form>
    </div>
  );
};

export default ThreatInputForm;