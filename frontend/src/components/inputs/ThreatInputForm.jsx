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
  const [aiResult, setAiResult] = useState(null);

  const inputTypes = [
    { value: 'ip', label: 'IP Address', placeholder: 'e.g., 192.168.1.1' },
    { value: 'domain', label: 'Domain', placeholder: 'e.g., example.com' },
    { value: 'url', label: 'URL', placeholder: 'e.g., https://example.com/malicious' },
    { value: 'hash', label: 'Hash (MD5/SHA1/SHA256)', placeholder: 'e.g., a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3' },
    { value: 'network', label: 'Network Traffic', placeholder: 'e.g., network anomaly or packet data' }
  ];

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    
    setFormData(prev => {
      const newFormData = {
        ...prev,
        [name]: type === 'checkbox' ? checked : value
      };
      return newFormData;
    });
  };

  const validateInput = () => {
    if (!formData.value.trim()) {
      setError('❌ Please enter a value');
      return false;
    }

    // Basic validation based on type
    switch (formData.type) {
      case 'ip':
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(formData.value)) {
          setError('❌ Please enter a valid IP address (e.g., 192.168.1.1)');
          return false;
        }
        break;
      case 'domain':
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        if (!domainRegex.test(formData.value)) {
          setError('❌ Please enter a valid domain name (e.g., example.com)');
          return false;
        }
        break;
      case 'url':
        try {
          new URL(formData.value);
        } catch {
          setError('❌ Please enter a valid URL (e.g., https://example.com)');
          return false;
        }
        break;
      case 'hash':
        const hashRegex = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
        if (!hashRegex.test(formData.value)) {
          setError('❌ Please enter a valid hash (MD5/SHA1/SHA256)');
          return false;
        }
        break;
      case 'network':
        const trimmedValue = formData.value.trim();
        
        if (trimmedValue.length < 3) {
          setError('❌ Please enter a descriptive network indicator (at least 3 characters)');
          return false;
        }
        
        // Check for meaningful content
        if (!/[a-zA-Z0-9]/.test(trimmedValue)) {
          setError('❌ Network indicator must contain meaningful text or data');
          return false;
        }
        break;
      default:
        setError(`❌ Unsupported IOC type: ${formData.type}`);
        return false;
    }

    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Clear previous states
    setError('');
    setMessage('');
    setAiResult(null);

    // Validate input
    if (!validateInput()) {
      return;
    }
    
    setLoading(true);

    try {
      const response = await ingestionApi.submitSingleInput(formData);
      
      const successMessage = response.message || '✅ Threat input submitted successfully!';
      setMessage(successMessage);

      // Display AI prediction result
      if (response.data && response.data.ai_prediction) {
        setAiResult(response.data.ai_prediction);
      }

      // Clear form value but keep type and monitoring setting
      setFormData(prev => ({ ...prev, value: '' }));
      
    } catch (err) {
      const errorMessage = err.message || '❌ Failed to submit threat input';
      setError(errorMessage);
      
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

          {aiResult && (
            <div className={`glass-card p-4 border-2 ${
              aiResult.prediction === 'malicious'
                ? 'border-red-500/30 bg-red-500/10'
                : aiResult.prediction === 'benign'
                ? 'border-green-500/30 bg-green-500/10'
                : 'border-yellow-500/30 bg-yellow-500/10'
            }`}>
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-lg font-semibold">AI Analysis Result</h4>
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                  aiResult.prediction === 'malicious'
                    ? 'bg-red-500/20 text-red-300'
                    : aiResult.prediction === 'benign'
                    ? 'bg-green-500/20 text-green-300'
                    : 'bg-yellow-500/20 text-yellow-300'
                }`}>
                  {aiResult.prediction.toUpperCase()}
                </span>
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="opacity-80">IOC Type:</span>
                  <span className="font-medium">{aiResult.ioc_type.toUpperCase()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="opacity-80">Confidence:</span>
                  <span className="font-medium">{(aiResult.confidence * 100).toFixed(1)}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="opacity-80">Model:</span>
                  <span className="font-medium">{aiResult.model_name}</span>
                </div>
              </div>

              {aiResult.explanation && (
                <div className="mt-4">
                  <details className="cursor-pointer">
                    <summary className="text-sm font-medium opacity-80 hover:opacity-100">
                      View Detailed Analysis
                    </summary>
                    <div className="mt-2 p-3 bg-black/20 rounded text-xs whitespace-pre-line max-h-60 overflow-y-auto">
                      {aiResult.explanation}
                    </div>
                  </details>
                </div>
              )}
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