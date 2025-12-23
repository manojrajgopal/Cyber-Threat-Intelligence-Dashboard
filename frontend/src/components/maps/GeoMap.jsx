import React from 'react';
import './GeoMap.css';

const GeoMap = () => {
  return (
    <div className="glass-content">
      <div className="glass-card glass-fade-in">
        <div className="glass-card-header">
          <h1 className="glass-card-title">Threat Geolocation Map</h1>
        </div>
      </div>

      <div className="glass-card glass-fade-in">
        <div className="glass-card-content">
          <div className="h-96 glass-card flex items-center justify-center">
            <div className="text-center">
              <p className="opacity-70">Interactive threat map would be displayed here</p>
              <p className="text-sm opacity-50 mt-2">
                (Integration with mapping library like Leaflet or Google Maps required)
              </p>
            </div>
          </div>

          <div className="mt-6">
            <h2 className="text-lg font-medium mb-4 opacity-90">Map Features</h2>
            <ul className="space-y-2 opacity-70">
              <li className="flex items-center">
                <span className="mr-2">📍</span>
                Display IOCs with geolocation data
              </li>
              <li className="flex items-center">
                <span className="mr-2">🎨</span>
                Color-coded markers based on risk score
              </li>
              <li className="flex items-center">
                <span className="mr-2">💬</span>
                Interactive tooltips with IOC details
              </li>
              <li className="flex items-center">
                <span className="mr-2">📊</span>
                Clustering for dense areas
              </li>
              <li className="flex items-center">
                <span className="mr-2">🔍</span>
                Filter by IOC type and time range
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GeoMap;