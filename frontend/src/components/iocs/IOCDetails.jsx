import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../../services/api';
import './IOCDetails.css';

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
    return <div className="flex justify-center items-center h-64">Loading...</div>;
  }

  if (!ioc) {
    return <div className="p-6">IOC not found</div>;
  }

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">IOC Details</h1>
        <Link
          to={`/iocs/${id}/intelligence`}
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
        >
          View AI Intelligence
        </Link>
      </div>
      
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h2 className="text-xl font-semibold mb-4">Basic Information</h2>
            <div className="space-y-2">
              <div>
                <span className="font-medium">Type:</span>
                <span className="ml-2 px-2 py-1 bg-blue-100 text-blue-800 rounded text-sm">
                  {ioc.type}
                </span>
              </div>
              <div>
                <span className="font-medium">Value:</span>
                <span className="ml-2">{ioc.value}</span>
              </div>
              <div>
                <span className="font-medium">Source:</span>
                <span className="ml-2">{ioc.source}</span>
              </div>
              <div>
                <span className="font-medium">Risk Score:</span>
                <span className={`ml-2 px-2 py-1 rounded text-sm ${
                  ioc.risk_score >= 0.7 ? 'bg-red-100 text-red-800' :
                  ioc.risk_score >= 0.4 ? 'bg-yellow-100 text-yellow-800' :
                  'bg-green-100 text-green-800'
                }`}>
                  {(ioc.risk_score * 100).toFixed(1)}%
                </span>
              </div>
              <div>
                <span className="font-medium">Enriched:</span>
                <span className={`ml-2 px-2 py-1 rounded text-sm ${
                  ioc.enriched ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                }`}>
                  {ioc.enriched ? 'Yes' : 'No'}
                </span>
              </div>
              <div>
                <span className="font-medium">First Seen:</span>
                <span className="ml-2">
                  {ioc.first_seen ? new Date(ioc.first_seen).toLocaleString() : 'N/A'}
                </span>
              </div>
              <div>
                <span className="font-medium">Last Seen:</span>
                <span className="ml-2">
                  {ioc.last_seen ? new Date(ioc.last_seen).toLocaleString() : 'N/A'}
                </span>
              </div>
            </div>
          </div>
          
          <div>
            <h2 className="text-xl font-semibold mb-4">Enrichment Data</h2>
            {ioc.enrichments && ioc.enrichments.length > 0 ? (
              <div className="space-y-4">
                {ioc.enrichments.map((enrichment, index) => (
                  <div key={index} className="border rounded p-3">
                    <h3 className="font-medium capitalize">{enrichment.enrichment_type}</h3>
                    <pre className="text-sm text-gray-600 mt-2 whitespace-pre-wrap">
                      {JSON.stringify(enrichment.data, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-500">No enrichment data available</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default IOCDetails;