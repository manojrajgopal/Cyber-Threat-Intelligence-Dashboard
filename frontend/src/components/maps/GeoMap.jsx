import React, { useState, useEffect } from 'react';

import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';

import 'leaflet/dist/leaflet.css';

import { getMapIOCs } from '../../api/mapApi';

import './GeoMap.css';

const GeoMap = () => {
    const [iocs, setIocs] = useState([]);

    useEffect(() => {
        const fetchIOCs = async () => {
            const data = await getMapIOCs();
            setIocs(data);
        };
        fetchIOCs();
    }, []);

    return (
        <div className="glass-content">
            <div className="glass-card glass-fade-in">
                <div className="glass-card-header">
                    <h1 className="glass-card-title">Threat Geolocation Map</h1>
                </div>
            </div>

            <div className="glass-card glass-fade-in">
                <div className="glass-card-content">
                    <MapContainer center={[20, 0]} zoom={2} style={{ height: '500px', width: '100%' }}>
                        <TileLayer
                            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                        />
                        {iocs.map(ioc => (
                            <Marker key={ioc.id} position={[ioc.lat, ioc.lon]}>
                                <Popup>
                                    <strong>{ioc.type.toUpperCase()}: {ioc.value}</strong><br />
                                    Risk Score: {ioc.risk_score}<br />
                                    Location: {ioc.city}, {ioc.country}
                                </Popup>
                            </Marker>
                        ))}
                    </MapContainer>

                    <div className="mt-6">
                        <h2 className="text-lg font-medium mb-4 opacity-90">Map Statistics</h2>
                        <p>Total IOCs on map: {iocs.length}</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default GeoMap;