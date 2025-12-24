import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../../services/api';

const IOCDetails = () => {
  const { id } = useParams();
  const [ioc, setIoc] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIOC();
  }, [id]);

  const fetchIOC = async () => {
    try {
      const response = await api.get(`/iocs/${id}`);
      setIoc(response.data);
    } catch (error) {
      console.error('Error fetching IOC:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16">
          Loading...
        </div>
      </div>
    );
  }

  if (!ioc) {
    return (
      <div className="glass-card">
        <div className="glass-card-content">
          IOC not found
        </div>
      </div>
    );
  }

  return (
    <div className="glass-card">
      <div className="glass-card-header">
        <h1 className="glass-card-title text-3xl">IOC Details</h1>
        <Link
          to={`/iocs/${id}/intelligence`}
          className="glass-button primary"
        >
          View AI Intelligence
        </Link>
      </div>

      <div className="glass-card-content">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h2 className="text-xl font-semibold mb-4 text-black">Basic Information</h2>
            <div className="space-y-2">
              <div>
                <span className="font-medium">Type:</span>
                <span className="ml-2 px-2 py-1 bg-amber-500/20 text-amber-300 rounded text-sm">
                  {ioc.type}
                </span>
              </div>
              <div>
                <span className="font-medium text-black">Value:</span>
                <span className="ml-2 text-black">{ioc.value}</span>
              </div>
              <div>
                <span className="font-medium text-black">Source:</span>
                <span className="ml-2 text-black">{ioc.source}</span>
              </div>
              <div>
                <span className="font-medium text-black">Risk Score:</span>
                <span className={`ml-2 px-2 py-1 rounded text-sm ${
                  ioc.risk_score >= 0.7 ? 'bg-red-500/20 text-red-300' :
                  ioc.risk_score >= 0.4 ? 'bg-yellow-500/20 text-yellow-300' :
                  'bg-green-500/20 text-green-300'
                }`}>
                  {(ioc.risk_score * 100).toFixed(1)}%
                </span>
              </div>
              <div>
                <span className="font-medium text-black">Enriched:</span>
                <span className={`ml-2 px-2 py-1 rounded text-sm ${
                  ioc.enriched ? 'bg-green-500/20 text-green-300' : 'bg-gray-500/20 text-gray-300'
                }`}>
                  {ioc.enriched ? 'Yes' : 'No'}
                </span>
              </div>
              <div>
                <span className="font-medium text-black">First Seen:</span>
                <span className="ml-2 text-black">
                  {ioc.first_seen ? new Date(ioc.first_seen).toLocaleString() : 'N/A'}
                </span>
              </div>
              <div>
                <span className="font-medium text-black">Last Seen:</span>
                <span className="ml-2 text-black">
                  {ioc.last_seen ? new Date(ioc.last_seen).toLocaleString() : 'N/A'}
                </span>
              </div>
            </div>
          </div>
          
          <div>
            <h2 className="text-xl font-semibold mb-4 text-black">Enrichment Data</h2>
            {ioc.enrichments && ioc.enrichments.length > 0 ? (
              <div className="space-y-4">
                {ioc.enrichments.map((enrichment, index) => (
                  <div key={index} className="glass-card p-3">
                    <h3 className="font-medium capitalize text-black">{enrichment.enrichment_type}</h3>
                    <pre className="text-sm opacity-70 mt-2 whitespace-pre-wrap">
                      {JSON.stringify(enrichment.data, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            ) : (
              <p className="opacity-70">No enrichment data available</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default IOCDetails;