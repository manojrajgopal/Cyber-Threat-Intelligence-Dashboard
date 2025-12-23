import React, { useState, useEffect } from 'react';
import api from '../services/api';
import './AIInsightsPage.css';

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
    return (
      <div className="glass-card">
        <div className="glass-card-content text-center py-16">
          Loading AI insights...
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

  return (
    <div className="glass-content">
      <div className="glass-card glass-fade-in">
        <div className="glass-card-header">
          <h1 className="glass-card-title">AI Intelligence & Insights</h1>
        </div>
        <div className="glass-card-content">
          <p className="opacity-70">
            Advanced AI analysis, behavioral patterns, and threat correlations
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Behavioral Analysis */}
        {insights.behavioral && (
          <div className="glass-card glass-fade-in">
            <div className="glass-card-header">
              <h2 className="glass-card-title">Behavioral Analysis</h2>
            </div>
            <div className="glass-card-content space-y-6">
              {/* Repeated Behaviors */}
              {insights.behavioral.repeated_behaviors && insights.behavioral.repeated_behaviors.length > 0 && (
                <div>
                  <h3 className="text-lg font-medium mb-3 opacity-90">Repeated IOC Behaviors</h3>
                  <div className="space-y-3">
                    {insights.behavioral.repeated_behaviors.slice(0, 5).map((behavior, index) => (
                      <div key={index} className="glass-card p-4 border-yellow-500/20 bg-yellow-500/5">
                        <div className="font-medium">{behavior.ioc_value}</div>
                        <div className="text-sm opacity-70">
                          {behavior.occurrences} occurrences, avg interval: {behavior.avg_interval_hours?.toFixed(1)} hours
                        </div>
                        {behavior.is_suspicious && (
                          <div className="text-sm text-red-300 font-medium">⚠️ Suspicious pattern detected</div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Lateral Movement */}
              {insights.behavioral.lateral_movement && insights.behavioral.lateral_movement.length > 0 && (
                <div>
                  <h3 className="text-lg font-medium mb-3 opacity-90">Lateral Movement Indicators</h3>
                  <div className="space-y-3">
                    {insights.behavioral.lateral_movement.slice(0, 3).map((movement, index) => (
                      <div key={index} className="glass-card p-4 border-red-500/20 bg-red-500/5">
                        <div className="font-medium">Time: {new Date(movement.time_window).toLocaleString()}</div>
                        <div className="text-sm opacity-70">
                          {movement.alert_count} alerts, {movement.ioc_types?.length} IOC types
                        </div>
                        <div className={`text-sm font-medium ${
                          movement.severity === 'high' ? 'text-red-300' : 'text-orange-300'
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
                  <h3 className="text-lg font-medium mb-3 opacity-90">Detected Campaigns</h3>
                  <div className="space-y-3">
                    {insights.behavioral.campaigns.slice(0, 3).map((campaign, index) => (
                      <div key={index} className="glass-card p-4 border-purple-500/20 bg-purple-500/5">
                        <div className="font-medium">{campaign.campaign_id}</div>
                        <div className="text-sm opacity-70">
                          {campaign.size} IOCs, Risk: {(campaign.avg_risk_score * 100).toFixed(1)}%
                        </div>
                        <div className="text-sm text-purple-300">
                          {campaign.is_campaign ? 'Active Campaign' : 'Potential Campaign'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Threat Correlations */}
        {insights.correlations && insights.correlations.length > 0 && (
          <div className="glass-card glass-fade-in">
            <div className="glass-card-header">
              <h2 className="glass-card-title">Threat Correlations</h2>
            </div>
            <div className="glass-card-content">
              <div className="space-y-4">
                {insights.correlations.slice(0, 5).map((component, index) => (
                  <div key={index} className="glass-card p-4">
                    <div className="flex justify-between items-start mb-2">
                      <span className="font-medium">{component.component_id}</span>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        component.is_campaign ? 'bg-red-500/20 text-red-300' : 'bg-blue-500/20 text-blue-300'
                      }`}>
                        {component.is_campaign ? 'Campaign' : 'Cluster'}
                      </span>
                    </div>
                    <div className="text-sm opacity-70 mb-2">
                      Size: {component.size} | Risk: {(component.avg_risk_score * 100).toFixed(1)}%
                    </div>
                    <div className="text-sm opacity-80">
                      Types: {component.ioc_types?.join(', ')}
                    </div>
                    {component.ioc_samples && (
                      <div className="text-xs opacity-60 mt-1">
                        Samples: {component.ioc_samples.slice(0, 2).join(', ')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Temporal Analysis */}
      <div className="glass-card glass-fade-in">
        <div className="glass-card-header">
          <h2 className="glass-card-title">Recent Temporal Analysis</h2>
        </div>
        <div className="glass-card-content">
          <div className="text-center py-8 opacity-70">
            <p>Advanced temporal correlation analysis available</p>
            <p className="text-sm">Detects time-based patterns and anomaly bursts</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AIInsightsPage;