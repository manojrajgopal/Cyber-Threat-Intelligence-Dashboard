import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import api from '../../services/api';

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
      // Failed to load user info
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
        setAiPredictions([]);
      }

      // Load relationships
      try {
        const relResponse = await api.get(`/correlation/relationships/${id}`);
        setRelationships(relResponse.data || []);
      } catch (relErr) {
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
      // Failed to delete analysis
    }
  };

  const handleSingleDeleteAnalysis = async () => {
    try {
      await api.delete(`/ai/predictions/${predictionToDelete}`);
      setAiPredictions(prev => prev.filter(p => p.id !== predictionToDelete));
      setShowSingleDeleteModal(false);
      setPredictionToDelete(null);
    } catch (err) {
      // Failed to delete prediction
    }
  };
  
  if (loading) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16">
          Loading IOC intelligence...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16 text-red-300">
          {error}
        </div>
      </div>
    );
  }

  if (!ioc) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16">
          IOC not found
        </div>
      </div>
    );
  }

  return (
    <div className="glass-content">
      <div className="glass-card glass-fade-in">
        <div className="glass-card-header">
          <h1 className="glass-card-title">IOC Intelligence: {ioc.value}</h1>
          <div className="opacity-70 text-sm">
            Analyzed: {ioc.created_at ? new Date(ioc.created_at).toLocaleString() : 'N/A'}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          {/* IOC Details Panel */}
          <div className="glass-card glass-fade-in">
            <div className="glass-card-header">
              <h3 className="glass-card-title">IOC Details</h3>
            </div>
            <div className="glass-card-content">
              <div className="space-y-4">
                <div>
                  <div className="opacity-70 text-sm">Type</div>
                  <div className="font-medium">{ioc.type}</div>
                </div>
                <div>
                  <div className="opacity-70 text-sm">Risk Score</div>
                  <div className="font-medium">{ioc.risk_score}</div>
                </div>
                <div>
                  <div className="opacity-70 text-sm">Source</div>
                  <div className="font-medium">{ioc.source || 'Unknown'}</div>
                </div>
                <div>
                  <div className="opacity-70 text-sm">Enriched</div>
                  <div className="font-medium">{ioc.enriched ? 'Yes' : 'No'}</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 space-y-6">
          {/* AI Analysis Card */}
          <div className="glass-card glass-fade-in">
            <div className="glass-card-header">
              <h2 className="glass-card-title">AI Analysis</h2>
              <div>
                <button
                  onClick={runAIAnalysis}
                  disabled={aiLoading}
                  className="glass-button primary"
                >
                  {aiLoading ? 'Analyzing...' : aiPredictions.length > 0 ? '🔄 Analyze Again' : '🚀 Run AI Analysis'}
                </button>
                {currentUser && currentUser.role && currentUser.role.name === 'admin' && aiPredictions.length > 0 && (
                  <button
                    onClick={() => setShowDeleteModal(true)}
                    className="glass-button danger ml-2"
                  >
                    🗑️ Delete Analysis
                  </button>
                )}
              </div>
            </div>
            <div className="glass-card-content">
              {aiError && (
                <div className="text-red-300 mb-4">{aiError}</div>
              )}
              {aiPredictions.length > 0 ? (
                <div className="space-y-4">
                  {aiPredictions.map((prediction, index) => (
                    <div key={index} className="glass-card p-4">
                      <div className="flex justify-between items-start mb-4">
                        <div>
                          <h3 className="font-medium">AI Analysis Result</h3>
                          <p className="text-sm opacity-70">Threat Intelligence Classification</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-1 text-xs rounded-full ${
                            prediction.prediction === 'malicious' ? 'bg-red-500/20 text-red-300' :
                            prediction.prediction === 'suspicious' ? 'bg-yellow-500/20 text-yellow-300' :
                            'bg-green-500/20 text-green-300'
                          }`}>
                            {prediction.prediction === 'malicious' && '🚨 '}
                            {prediction.prediction === 'suspicious' && '⚠️ '}
                            {prediction.prediction === 'benign' && '✅ '}
                            {prediction.prediction.charAt(0).toUpperCase() + prediction.prediction.slice(1)}
                          </span>
                          {currentUser && currentUser.role && currentUser.role.name === 'admin' && (
                            <button
                              onClick={() => { setPredictionToDelete(prediction.id); setShowSingleDeleteModal(true); }}
                              className="glass-button danger text-xs px-2 py-1"
                              title="Delete this analysis result"
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </div>
                      <div>
                        <div className="flex justify-between text-sm opacity-70 mb-2">
                          <span>Confidence Level</span>
                          <span>{(prediction.confidence * 100).toFixed(1)}%</span>
                        </div>
                        <div className="w-full bg-gray-500/20 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full ${
                              prediction.prediction === 'malicious' ? 'bg-red-500' :
                              prediction.prediction === 'suspicious' ? 'bg-yellow-500' :
                              'bg-green-500'
                            }`}
                            style={{ width: `${prediction.confidence * 100}%` }}
                          ></div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 opacity-70">
                  <p>No AI analysis available. Click "Run AI Analysis" to get predictions.</p>
                </div>
              )}
            </div>
          </div>

          {/* Relationships Card */}
          {relationships.length > 0 && (
            <div className="glass-card glass-fade-in">
              <div className="glass-card-header">
                <h2 className="glass-card-title">Related IOCs</h2>
              </div>
              <div className="glass-card-content">
                <div className="overflow-x-auto">
                  <table className="glass-table w-full">
                    <thead>
                      <tr>
                        <th>Related IOC</th>
                        <th>Type</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {relationships.map((rel, index) => (
                        <tr key={index}>
                          <td>{rel.related_value}</td>
                          <td>{rel.related_type}</td>
                          <td>{(rel.confidence * 100).toFixed(1)}%</td>
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
            <div className="glass-card glass-fade-in">
              <div className="glass-card-header">
                <h2 className="glass-card-title">Enrichment Data</h2>
              </div>
              <div className="glass-card-content">
                <div className="space-y-4">
                  {ioc.enrichments.map((enrichment, index) => (
                    <div key={index}>
                      <h3 className="font-medium mb-2">{enrichment.enrichment_type}</h3>
                      <pre className="glass-card p-2 text-xs overflow-x-auto">
                        {JSON.stringify(enrichment.data, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Delete All Confirmation Modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="glass-card max-w-md w-full mx-4">
            <div className="glass-card-header">
              <h2 className="glass-card-title">Confirm Delete All Analyses</h2>
            </div>
            <div className="glass-card-content">
              {deleteAllStep === 0 ? (
                <>
                  <p className="opacity-80 mb-4">Are you sure you want to delete all AI analysis results for this IOC?</p>
                  <div className="flex gap-2 justify-end">
                    <button onClick={() => { setShowDeleteModal(false); setDeleteAllStep(0); }} className="glass-button">Cancel</button>
                    <button onClick={() => setDeleteAllStep(1)} className="glass-button danger">Next</button>
                  </div>
                </>
              ) : (
                <>
                  <p className="opacity-80 mb-4">This action is irreversible. All analysis results will be permanently deleted.</p>
                  <div className="flex gap-2 justify-end">
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
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="glass-card max-w-md w-full mx-4">
            <div className="glass-card-header">
              <h2 className="glass-card-title">Confirm Delete</h2>
            </div>
            <div className="glass-card-content">
              <p className="opacity-80 mb-4">Are you sure you want to delete this analysis result?</p>
              <div className="flex gap-2 justify-end">
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