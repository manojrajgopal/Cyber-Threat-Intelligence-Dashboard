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

  useEffect(() => {
    if (id) {
      loadIOCData();
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
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">IOC Intelligence: {ioc.value}</h1>
        <div className="mt-2 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-blue-50 p-3 rounded">
            <div className="text-sm text-blue-600">Type</div>
            <div className="font-semibold">{ioc.type}</div>
          </div>
          <div className="bg-green-50 p-3 rounded">
            <div className="text-sm text-green-600">Risk Score</div>
            <div className="font-semibold">{ioc.risk_score}</div>
          </div>
          <div className="bg-yellow-50 p-3 rounded">
            <div className="text-sm text-yellow-600">Source</div>
            <div className="font-semibold">{ioc.source || 'Unknown'}</div>
          </div>
          <div className="bg-purple-50 p-3 rounded">
            <div className="text-sm text-purple-600">Enriched</div>
            <div className="font-semibold">{ioc.enriched ? 'Yes' : 'No'}</div>
          </div>
        </div>
      </div>

      {/* AI Predictions */}
      {aiPredictions.length > 0 && (
        <div className="mb-6">
          <h2 className="text-xl font-semibold mb-4">AI Analysis</h2>
          <div className="space-y-4">
            {aiPredictions.map((prediction, index) => (
              <div key={index} className="bg-white border rounded-lg p-4">
                <div className="flex justify-between items-start mb-2">
                  <span className="font-medium">{prediction.model_name}</span>
                  <span className={`px-2 py-1 rounded text-sm ${
                    prediction.prediction === 'malicious'
                      ? 'bg-red-100 text-red-800'
                      : 'bg-green-100 text-green-800'
                  }`}>
                    {prediction.prediction}
                  </span>
                </div>
                <div className="text-sm text-gray-600">
                  Confidence: {(prediction.confidence * 100).toFixed(1)}%
                </div>
                {prediction.explanation && (
                  <div className="mt-2 text-sm text-gray-700">
                    {prediction.explanation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Relationships */}
      {relationships.length > 0 && (
        <div className="mb-6">
          <h2 className="text-xl font-semibold mb-4">Related IOCs</h2>
          <div className="bg-white border rounded-lg overflow-hidden">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-2 text-left text-sm font-medium text-gray-700">Related IOC</th>
                  <th className="px-4 py-2 text-left text-sm font-medium text-gray-700">Type</th>
                  <th className="px-4 py-2 text-left text-sm font-medium text-gray-700">Relationship</th>
                  <th className="px-4 py-2 text-left text-sm font-medium text-gray-700">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {relationships.map((rel, index) => (
                  <tr key={index}>
                    <td className="px-4 py-2 text-sm">{rel.related_value}</td>
                    <td className="px-4 py-2 text-sm">{rel.related_type}</td>
                    <td className="px-4 py-2 text-sm">{rel.relationship_type}</td>
                    <td className="px-4 py-2 text-sm">{(rel.confidence * 100).toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Enrichment Data */}
      {ioc.enrichments && ioc.enrichments.length > 0 && (
        <div className="mb-6">
          <h2 className="text-xl font-semibold mb-4">Enrichment Data</h2>
          <div className="space-y-4">
            {ioc.enrichments.map((enrichment, index) => (
              <div key={index} className="bg-white border rounded-lg p-4">
                <h3 className="font-medium mb-2">{enrichment.enrichment_type}</h3>
                <pre className="text-sm bg-gray-50 p-2 rounded overflow-x-auto">
                  {JSON.stringify(enrichment.data, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default IOCIntelligence;