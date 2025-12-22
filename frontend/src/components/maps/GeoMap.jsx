import React from 'react';

const GeoMap = () => {
  return (
    <div className="p-6">
      <h1 className="text-3xl font-bold mb-6">Threat Geolocation Map</h1>
      
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="h-96 bg-gray-100 rounded flex items-center justify-center">
          <p className="text-gray-500">Interactive threat map would be displayed here</p>
          <p className="text-sm text-gray-400 mt-2">
            (Integration with mapping library like Leaflet or Google Maps required)
          </p>
        </div>
        
        <div className="mt-4">
          <h2 className="text-lg font-semibold mb-2">Map Features</h2>
          <ul className="list-disc list-inside text-gray-600 space-y-1">
            <li>Display IOCs with geolocation data</li>
            <li>Color-coded markers based on risk score</li>
            <li>Interactive tooltips with IOC details</li>
            <li>Clustering for dense areas</li>
            <li>Filter by IOC type and time range</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default GeoMap;