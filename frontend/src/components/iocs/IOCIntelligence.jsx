import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import api from '../../services/api';
import './IOCIntelligence.css';

const IOCIntelligence = () => {
  const { id } = useParams();
  const [ioc, setIoc] = useState(null);
  const [aiPredictions, setAiPredictions] = useState([]);
  const [relationships, setRelationships] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');
  
  const [currentUser, setCurrentUser] = useState(null);
  
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteAllStep, setDeleteAllStep] = useState(0);
  const [showSingleDeleteModal, setShowSingleDeleteModal] = useState(false);
  const [predictionToDelete, setPredictionToDelete] = useState(null);
  
  const loadUser = async () => {
    try {
      const userResponse = await api.get('/users/me');
      setCurrentUser(userResponse.data);
    } catch (err) {
      console.log('Failed to load user info');
    }
  };
  
  useEffect(() => {
    if (id) {
      loadIOCData();
      loadUser();
    }
  }, [id]);

  const loadIOCData = async () => {
    try {
      setLoading(true);

      // Load IOC details
      const iocResponse = await api.get(`/iocs/${id}`);
      setIoc(iocResponse.data);

      // Load AI predictions for this IOC
      try {
        const aiResponse = await api.get(`/ai/predictions/${id}`);
        setAiPredictions(aiResponse.data || []);
      } catch (aiErr) {
        console.log('AI predictions not available');
        setAiPredictions([]);
      }

      // Load relationships
      try {
        const relResponse = await api.get(`/correlation/relationships/${id}`);
        setRelationships(relResponse.data || []);
      } catch (relErr) {
        console.log('Relationships not available');
        setRelationships([]);
      }

    } catch (err) {
      setError('Failed to load IOC intelligence data');
    } finally {
      setLoading(false);
    }
  };

  const runAIAnalysis = async () => {
    try {
      setAiLoading(true);
      setAiError('');
      setAiPredictions([]); // Clear any existing predictions

      // Trigger AI classification
      const response = await api.post(`/ai/classify/${id}`);

      // Reload AI predictions after successful classification
      const aiResponse = await api.get(`/ai/predictions/${id}`);
      const predictions = aiResponse.data || [];

      // Ensure we have valid prediction data
      if (predictions.length > 0) {
        setAiPredictions(predictions);
      } else {
        setAiError('AI analysis completed but no predictions were returned. Please try again.');
        setAiPredictions([]);
      }
    } catch (err) {
      setAiError('Failed to run AI analysis. Please try again.');
      console.error('AI analysis error:', err);
      setAiPredictions([]);
    } finally {
      setAiLoading(false);
    }
  };
  
  const handleDeleteAnalysis = async () => {
    try {
      await api.delete(`/ai/predictions/ioc/${id}`);
      setAiPredictions([]);
      setShowDeleteModal(false);
      setDeleteAllStep(0);
    } catch (err) {
      console.error('Failed to delete analysis');
    }
  };

  const handleSingleDeleteAnalysis = async () => {
    try {
      await api.delete(`/ai/predictions/${predictionToDelete}`);
      setAiPredictions(prev => prev.filter(p => p.id !== predictionToDelete));
      setShowSingleDeleteModal(false);
      setPredictionToDelete(null);
    } catch (err) {
      console.error('Failed to delete prediction');
    }
  };
  
  if (loading) {
    return <div className="p-6">Loading IOC intelligence...</div>;
  }

  if (error) {
    return <div className="p-6 text-red-600">{error}</div>;
  }

  if (!ioc) {
    return <div className="p-6">IOC not found</div>;
  }

  return (
    <div className="ioc-dashboard">
      <div className="dashboard-container">
        <div className="main-dashboard-panel fade-in">
          <div className="dashboard-header">
            <h1 className="header-title">IOC Intelligence: {ioc.value}</h1>
            <div className="timestamp-badge">
              Analyzed: {ioc.created_at ? new Date(ioc.created_at).toLocaleString() : 'N/A'}
            </div>
          </div>
          <div className="dashboard-content">
            <div className="nav-panel">
              <h3>Navigation</h3>
              <div className="nav-placeholder">Visual Panel</div>
            </div>
            <div className="main-content">
              {/* IOC Details Card */}
              <div className="glass-card fade-in">
                <div className="card-header">
                  <h2 className="card-title">IOC Details</h2>
                </div>
                <div className="card-content">
                  <div className="metric-grid">
                    <div className="metric-item">
                      <div className="metric-label">Type</div>
                      <div className="metric-value">{ioc.type}</div>
                    </div>
                    <div className="metric-item">
                      <div className="metric-label">Risk Score</div>
                      <div className="metric-value">{ioc.risk_score}</div>
                    </div>
                    <div className="metric-item">
                      <div className="metric-label">Source</div>
                      <div className="metric-value">{ioc.source || 'Unknown'}</div>
                    </div>
                    <div className="metric-item">
                      <div className="metric-label">Enriched</div>
                      <div className="metric-value">{ioc.enriched ? 'Yes' : 'No'}</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* AI Analysis Card */}
              <div className="glass-card fade-in ai-analysis-card">
                <div className="card-header">
                  <h2 className="card-title">AI Analysis</h2>
                  <div>
                    <button
                      onClick={runAIAnalysis}
                      disabled={aiLoading}
                      className="glass-button primary"
                    >
                      {aiLoading ? (
                        <>
                          <div className="loading-spinner"></div>
                          Analyzing...
                        </>
                      ) : aiPredictions.length > 0 ? '🔄 Analyze Again' : '🚀 Run AI Analysis'}
                    </button>
                    {currentUser && currentUser.role && currentUser.role.name === 'admin' && aiPredictions.length > 0 && (
                      <button
                        onClick={() => setShowDeleteModal(true)}
                        className="glass-button danger"
                        style={{ marginLeft: '0.5rem' }}
                      >
                        🗑️ Delete Analysis
                      </button>
                    )}
                  </div>
                </div>
                <div className="card-content">
                  {aiError && (
                    <div style={{ color: '#fca5a5', marginBottom: '1rem' }}>
                      {aiError}
                    </div>
                  )}
                  {aiPredictions.length > 0 ? (
                    <div>
                      {aiPredictions.map((prediction, index) => (
                        <div key={index} style={{ marginBottom: '1rem' }}>
                          <div className="prediction-header">
                            <div>
                              <h3 style={{ color: 'rgba(255,255,255,0.9)', margin: 0 }}>AI Analysis Result</h3>
                              <p style={{ color: 'rgba(255,255,255,0.6)', margin: '0.25rem 0' }}>Threat Intelligence Classification</p>
                            </div>
                            <span className={`prediction-badge ${prediction.prediction}`}>
                              {prediction.prediction === 'malicious' && '🚨 '}
                              {prediction.prediction === 'suspicious' && '⚠️ '}
                              {prediction.prediction === 'benign' && '✅ '}
                              {prediction.prediction.charAt(0).toUpperCase() + prediction.prediction.slice(1)}
                            </span>
                            {currentUser && currentUser.role && currentUser.role.name === 'admin' && (
                              <button
                                onClick={() => { setPredictionToDelete(prediction.id); setShowSingleDeleteModal(true); }}
                                className="glass-button danger"
                                style={{ marginLeft: '0.5rem', padding: '0.5rem 1rem', fontSize: '0.875rem' }}
                                title="Delete this analysis result"
                              >
                                Delete
                              </button>
                            )}
                          </div>
                          <div style={{ marginBottom: '1rem' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'rgba(255,255,255,0.6)', marginBottom: '0.25rem' }}>
                              <span>Confidence Level</span>
                              <span>{(prediction.confidence * 100).toFixed(1)}%</span>
                            </div>
                            <div className="confidence-bar">
                              <div
                                className={`confidence-fill ${prediction.prediction}`}
                                style={{ width: `${prediction.confidence * 100}%` }}
                              ></div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ textAlign: 'center', color: 'rgba(255,255,255,0.5)', padding: '2rem' }}>
                      <p>No AI analysis available. Click "Run AI Analysis" to get predictions.</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Placeholder for charts/maps */}
              <div className="glass-card fade-in">
                <div className="card-header">
                  <h2 className="card-title">Threat Visualization</h2>
                </div>
                <div className="card-content">
                  <p style={{ color: 'rgba(255,255,255,0.7)' }}>Charts and maps would go here</p>
                </div>
              </div>

              {/* Relationships Card */}
              {relationships.length > 0 && (
                <div className="glass-card fade-in">
                  <div className="card-header">
                    <h2 className="card-title">Related IOCs</h2>
                  </div>
                  <div className="card-content">
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', color: 'rgba(255,255,255,0.9)' }}>
                        <thead>
                          <tr>
                            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '1px solid rgba(255,255,255,0.2)' }}>Related IOC</th>
                            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '1px solid rgba(255,255,255,0.2)' }}>Type</th>
                            <th style={{ textAlign: 'left', padding: '0.5rem', borderBottom: '1px solid rgba(255,255,255,0.2)' }}>Confidence</th>
                          </tr>
                        </thead>
                        <tbody>
                          {relationships.map((rel, index) => (
                            <tr key={index}>
                              <td style={{ padding: '0.5rem' }}>{rel.related_value}</td>
                              <td style={{ padding: '0.5rem' }}>{rel.related_type}</td>
                              <td style={{ padding: '0.5rem' }}>{(rel.confidence * 100).toFixed(1)}%</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* Enrichment Card */}
              {ioc.enrichments && ioc.enrichments.length > 0 && (
                <div className="glass-card fade-in">
                  <div className="card-header">
                    <h2 className="card-title">Enrichment Data</h2>
                  </div>
                  <div className="card-content">
                    {ioc.enrichments.map((enrichment, index) => (
                      <div key={index} style={{ marginBottom: '1rem' }}>
                        <h3 style={{ color: 'rgba(255,255,255,0.9)', marginBottom: '0.5rem' }}>{enrichment.enrichment_type}</h3>
                        <pre style={{ background: 'rgba(255,255,255,0.1)', padding: '0.5rem', borderRadius: '4px', fontSize: '0.75rem', color: 'rgba(255,255,255,0.8)', overflowX: 'auto' }}>
                          {JSON.stringify(enrichment.data, null, 2)}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Delete All Confirmation Modal */}
      {showDeleteModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="glass-card" style={{ maxWidth: '400px', width: '100%', margin: '1rem' }}>
            <div className="card-header">
              <h2 className="card-title">Confirm Delete All Analyses</h2>
            </div>
            <div className="card-content">
              {deleteAllStep === 0 ? (
                <>
                  <p style={{ color: 'rgba(255,255,255,0.8)', marginBottom: '1rem' }}>Are you sure you want to delete all AI analysis results for this IOC?</p>
                  <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                    <button onClick={() => { setShowDeleteModal(false); setDeleteAllStep(0); }} className="glass-button">Cancel</button>
                    <button onClick={() => setDeleteAllStep(1)} className="glass-button danger">Next</button>
                  </div>
                </>
              ) : (
                <>
                  <p style={{ color: 'rgba(255,255,255,0.8)', marginBottom: '1rem' }}>This action is irreversible. All analysis results will be permanently deleted.</p>
                  <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                    <button onClick={() => setDeleteAllStep(0)} className="glass-button">Back</button>
                    <button onClick={handleDeleteAnalysis} className="glass-button danger">Delete All</button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Single Delete Confirmation Modal */}
      {showSingleDeleteModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="glass-card" style={{ maxWidth: '400px', width: '100%', margin: '1rem' }}>
            <div className="card-header">
              <h2 className="card-title">Confirm Delete</h2>
            </div>
            <div className="card-content">
              <p style={{ color: 'rgba(255,255,255,0.8)', marginBottom: '1rem' }}>Are you sure you want to delete this analysis result?</p>
              <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                <button onClick={() => { setShowSingleDeleteModal(false); setPredictionToDelete(null); }} className="glass-button">Cancel</button>
                <button onClick={handleSingleDeleteAnalysis} className="glass-button danger">Delete</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IOCIntelligence;