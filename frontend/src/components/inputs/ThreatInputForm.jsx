import React, { useState } from 'react';
import { ingestionApi } from '../../api/ingestionApi';
import './ThreatInputForm.css';

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
        // Support both regular domains and obfuscated domains with [.] notation
        const normalizedDomain = formData.value.replace(/\[\.\]/g, '.');
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        if (!domainRegex.test(normalizedDomain)) {
          setError('❌ Please enter a valid domain name (e.g., example.com or example[.])com)');
          return false;
        }
        break;
      case 'url':
        try {
          // Support URLs with [.] notation by normalizing them temporarily for validation
          const normalizedUrl = formData.value.replace(/\[\.\]/g, '.');
          new URL(normalizedUrl);
        } catch {
          setError('❌ Please enter a valid URL (e.g., https://example.com or https://example[.]com)');
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
            <div className={`glass-card p-5 border-2 ${
              aiResult.prediction === 'malicious'
                ? 'border-red-500/30 bg-red-500/10'
                : aiResult.prediction === 'benign'
                ? 'border-green-500/30 bg-green-500/10'
                : 'border-yellow-500/30 bg-yellow-500/10'
            }`}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <div className="w-3 h-3 rounded-full bg-gradient-to-r from-blue-400 to-purple-400 animate-pulse"></div>
                  <h4 className="text-lg font-bold text-white">AI Analysis Result</h4>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`px-4 py-2 rounded-full text-sm font-bold shadow-lg backdrop-blur-sm ${
                    aiResult.prediction === 'malicious'
                      ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                      : aiResult.prediction === 'benign'
                      ? 'bg-green-500/20 text-green-300 border border-green-500/30'
                      : 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                  }`}>
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${
                        aiResult.prediction === 'malicious'
                          ? 'bg-red-400'
                          : aiResult.prediction === 'benign'
                          ? 'bg-green-400'
                          : 'bg-yellow-400'
                      }`}></div>
                      <span>{aiResult.prediction.toUpperCase()}</span>
                    </div>
                  </span>
                </div>
              </div>

              <div className="bg-black/20 rounded-lg p-4 space-y-3 border border-white/10">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="flex flex-col space-y-1">
                    <span className="text-xs text-white/60 uppercase tracking-wider font-semibold">IOC Type</span>
                    <span className="text-sm font-bold text-white/90 bg-white/10 px-3 py-2 rounded-lg border border-white/20">
                      {aiResult.ioc_type.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex flex-col space-y-1">
                    <span className="text-xs text-white/60 uppercase tracking-wider font-semibold">Risk Score</span>
                    <div className="flex items-center space-x-2">
                      <div className="flex-1 bg-black/30 rounded-full h-2 border border-white/20">
                        <div 
                          className={`h-full rounded-full transition-all duration-500 ${
                            aiResult.risk_score >= 0.7
                              ? 'bg-gradient-to-r from-red-500 to-red-700'
                              : aiResult.risk_score >= 0.4
                              ? 'bg-gradient-to-r from-yellow-400 to-yellow-600'
                              : 'bg-gradient-to-r from-green-400 to-green-600'
                          }`}
                          style={{ width: `${(aiResult.risk_score || 0) * 100}%` }}
                        ></div>
                      </div>
                      <span className="text-sm font-bold text-white/90 min-w-[3rem]">
                        {aiResult.risk_score ? (aiResult.risk_score * 100).toFixed(1) : 'N/A'}%
                      </span>
                    </div>
                  </div>
                  <div className="flex flex-col space-y-1">
                    <span className="text-xs text-white/60 uppercase tracking-wider font-semibold">Confidence</span>
                    <div className="flex items-center space-x-2">
                      <div className="flex-1 bg-black/30 rounded-full h-2 border border-white/20">
                        <div 
                          className={`h-full rounded-full transition-all duration-500 ${
                            aiResult.prediction === 'malicious'
                              ? 'bg-gradient-to-r from-red-400 to-red-600'
                              : aiResult.prediction === 'benign'
                              ? 'bg-gradient-to-r from-green-400 to-green-600'
                              : 'bg-gradient-to-r from-yellow-400 to-yellow-600'
                          }`}
                          style={{ width: `${aiResult.confidence * 100}%` }}
                        ></div>
                      </div>
                      <span className="text-sm font-bold text-white/90 min-w-[3rem]">
                        {(aiResult.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                  </div>
                  <div className="flex flex-col space-y-1">
                    <span className="text-xs text-white/60 uppercase tracking-wider font-semibold">Model</span>
                    <span className="text-sm font-bold text-white/90 bg-white/10 px-3 py-2 rounded-lg border border-white/20">
                      {aiResult.model_name}
                    </span>
                  </div>
                </div>
              </div>

              {aiResult.explanation && (
                <div className="mt-4">
                  <details className="cursor-pointer group">
                    <summary className="flex items-center justify-between p-3 rounded-lg border border-white/10 hover:border-white/20 transition-all duration-300 hover:bg-white/5">
                      <div className="flex items-center space-x-2">
                        <div className="w-2 h-2 rounded-full bg-gradient-to-r from-blue-400 to-purple-400"></div>
                        <span className="text-sm font-semibold text-white/90">View Detailed Analysis</span>
                      </div>
                      <div className="transform group-open:rotate-180 transition-transform duration-300">
                        <svg className="w-4 h-4 text-white/60" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </div>
                    </summary>
                    <div className="mt-3 p-4 bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-white/10 rounded-lg backdrop-blur-sm">
                      <div className="space-y-3">
                        <div className="flex items-center space-x-2 mb-4">
                          <div className="w-1 h-4 bg-gradient-to-b from-blue-400 to-purple-400 rounded-full"></div>
                          <h5 className="text-sm font-semibold text-white/90">AI Analysis Details</h5>
                        </div>
                        <div className="bg-black/30 rounded-lg p-4 border border-white/5">
                          <pre className="text-xs text-white/80 whitespace-pre-wrap leading-relaxed font-mono max-h-80 overflow-y-auto scrollbar-thin scrollbar-track-slate-800 scrollbar-thumb-slate-600 hover:scrollbar-thumb-slate-500">
                            {aiResult.explanation}
                          </pre>
                        </div>
                        <div className="flex items-center justify-between pt-2 border-t border-white/10">
                          <span className="text-xs text-white/60">Generated by AI Analysis</span>
                          <div className="flex items-center space-x-1">
                            <div className="w-2 h-2 rounded-full bg-green-400/60 animate-pulse"></div>
                            <span className="text-xs text-white/60">Live Analysis</span>
                          </div>
                        </div>
                      </div>
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