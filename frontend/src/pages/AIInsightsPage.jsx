import React, { useState, useEffect } from 'react';
import api from '../services/api';

const AIInsightsPage = () => {
  const [insights, setInsights] = useState({
    predictions: [],
    behavioral: null,
    correlations: null
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadAIInsights();
  }, []);

  const loadAIInsights = async () => {
    try {
      setLoading(true);

      // Load behavioral insights
      const behavioralResponse = await api.get('/correlation/behavioral-insights');
      setInsights(prev => ({ ...prev, behavioral: behavioralResponse.data }));

      // Load campaigns
      const campaignsResponse = await api.get('/correlation/campaigns');
      setInsights(prev => ({ ...prev, correlations: campaignsResponse.data }));

    } catch (err) {
      setError('Failed to load AI insights');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="p-6">Loading AI insights...</div>;
  }

  if (error) {
    return <div className="p-6 text-red-600">{error}</div>;
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">AI Intelligence & Insights</h1>
        <p className="text-gray-600 mt-2">
          Advanced AI analysis, behavioral patterns, and threat correlations
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Behavioral Analysis */}
        {insights.behavioral && (
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4">Behavioral Analysis</h2>

            {/* Repeated Behaviors */}
            {insights.behavioral.repeated_behaviors && insights.behavioral.repeated_behaviors.length > 0 && (
              <div className="mb-4">
                <h3 className="text-lg font-medium mb-2">Repeated IOC Behaviors</h3>
                <div className="space-y-2">
                  {insights.behavioral.repeated_behaviors.slice(0, 5).map((behavior, index) => (
                    <div key={index} className="bg-yellow-50 p-3 rounded border">
                      <div className="font-medium">{behavior.ioc_value}</div>
                      <div className="text-sm text-gray-600">
                        {behavior.occurrences} occurrences, avg interval: {behavior.avg_interval_hours?.toFixed(1)} hours
                      </div>
                      {behavior.is_suspicious && (
                        <div className="text-sm text-red-600 font-medium">⚠️ Suspicious pattern detected</div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Lateral Movement */}
            {insights.behavioral.lateral_movement && insights.behavioral.lateral_movement.length > 0 && (
              <div className="mb-4">
                <h3 className="text-lg font-medium mb-2">Lateral Movement Indicators</h3>
                <div className="space-y-2">
                  {insights.behavioral.lateral_movement.slice(0, 3).map((movement, index) => (
                    <div key={index} className="bg-red-50 p-3 rounded border">
                      <div className="font-medium">Time: {new Date(movement.time_window).toLocaleString()}</div>
                      <div className="text-sm text-gray-600">
                        {movement.alert_count} alerts, {movement.ioc_types?.length} IOC types
                      </div>
                      <div className={`text-sm font-medium ${
                        movement.severity === 'high' ? 'text-red-600' : 'text-orange-600'
                      }`}>
                        Severity: {movement.severity}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Threat Campaigns */}
            {insights.behavioral.campaigns && insights.behavioral.campaigns.length > 0 && (
              <div>
                <h3 className="text-lg font-medium mb-2">Detected Campaigns</h3>
                <div className="space-y-2">
                  {insights.behavioral.campaigns.slice(0, 3).map((campaign, index) => (
                    <div key={index} className="bg-purple-50 p-3 rounded border">
                      <div className="font-medium">{campaign.campaign_id}</div>
                      <div className="text-sm text-gray-600">
                        {campaign.size} IOCs, Risk: {(campaign.avg_risk_score * 100).toFixed(1)}%
                      </div>
                      <div className="text-sm text-purple-600">
                        {campaign.is_campaign ? 'Active Campaign' : 'Potential Campaign'}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Threat Correlations */}
        {insights.correlations && insights.correlations.length > 0 && (
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4">Threat Correlations</h2>
            <div className="space-y-4">
              {insights.correlations.slice(0, 5).map((component, index) => (
                <div key={index} className="border rounded-lg p-4">
                  <div className="flex justify-between items-start mb-2">
                    <span className="font-medium">{component.component_id}</span>
                    <span className={`px-2 py-1 rounded text-sm ${
                      component.is_campaign ? 'bg-red-100 text-red-800' : 'bg-blue-100 text-blue-800'
                    }`}>
                      {component.is_campaign ? 'Campaign' : 'Cluster'}
                    </span>
                  </div>
                  <div className="text-sm text-gray-600 mb-2">
                    Size: {component.size} | Risk: {(component.avg_risk_score * 100).toFixed(1)}%
                  </div>
                  <div className="text-sm">
                    Types: {component.ioc_types?.join(', ')}
                  </div>
                  {component.ioc_samples && (
                    <div className="text-xs text-gray-500 mt-1">
                      Samples: {component.ioc_samples.slice(0, 2).join(', ')}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Temporal Analysis */}
      <div className="mt-6 bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-4">Recent Temporal Analysis</h2>
        <div className="text-center text-gray-500">
          <p>Advanced temporal correlation analysis available</p>
          <p className="text-sm">Detects time-based patterns and anomaly bursts</p>
        </div>
      </div>
    </div>
  );
};

export default AIInsightsPage;