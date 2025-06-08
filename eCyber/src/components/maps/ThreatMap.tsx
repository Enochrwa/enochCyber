import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup, CircleMarker } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import apiClient from '../../lib/apiClient'; // Assuming apiClient is set up

// Default icon fix for Leaflet
import iconRetinaUrl from 'leaflet/dist/images/marker-icon-2x.png';
import iconUrl from 'leaflet/dist/images/marker-icon.png';
import shadowUrl from 'leaflet/dist/images/marker-shadow.png';

L.Icon.Default.mergeOptions({
  iconRetinaUrl,
  iconUrl,
  shadowUrl,
});

interface GeolocatedThreat {
  source_ip: string;
  latitude: number | null;
  longitude: number | null;
  city: string | null;
  country: string | null;
  timestamp: string;
  threat_type: string;
  severity: string;
}

interface CountryCoordinate {
  lat: number;
  lng: number;
}

// Simplified lookup for demo purposes. In a real app, this would be more extensive
// or ideally, the backend would provide coordinates.
const countryCoordinates: Record<string, CountryCoordinate> = {
  "United States": { lat: 37.0902, lng: -95.7129 },
  "China": { lat: 35.8617, lng: 104.1954 },
  "Russia": { lat: 61.5240, lng: 105.3188 },
  "Germany": { lat: 51.1657, lng: 10.4515 },
  "United Kingdom": { lat: 55.3781, lng: -3.4360 },
  "Brazil": { lat: -14.2350, lng: -51.9253 },
  "India": { lat: 20.5937, lng: 78.9629 },
  "Canada": { lat: 56.1304, lng: -106.3468 },
  "France": { lat: 46.603354, lng: 1.8883335 },
  "Australia": { lat: -25.2744, lng: 133.7751 },
  // Add more countries as needed
};

const ThreatMap: React.FC = () => {
  const [threats, setThreats] = useState<GeolocatedThreat[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchGeoThreats = async () => {
      try {
        setLoading(true);
        // Use the new endpoint. Adjust params as needed.
        const response = await apiClient.get<GeolocatedThreat[]>('/api/v1/threats/geolocated?limit=100&hours=720'); // Fetch more data for better map
        setThreats(response.data);
        setError(null);
      } catch (err) {
        console.error("Error fetching geolocated threats:", err);
        setError("Failed to load threat data for map.");
        // Keep potentially stale data or clear it:
        // setThreats([]);
      } finally {
        setLoading(false);
      }
    };

    fetchGeoThreats();
    const intervalId = setInterval(fetchGeoThreats, 60000); // Refresh every minute

    return () => clearInterval(intervalId);
  }, []);

  if (loading && threats.length === 0) { // Show loading only on initial load
    return <div className="p-4 text-center">Loading map data...</div>;
  }

  if (error) {
    return <div className="p-4 text-center text-red-500">{error}</div>;
  }

  if (threats.length === 0 && !loading) {
    return <div className="p-4 text-center">No geolocated threat data available.</div>;
  }

  // Aggregate threats by country to display one marker per country
  const threatsByCountry: Record<string, { count: number; types: Set<string>; severities: Set<string> }> = {};

  threats.forEach(threat => {
    if (threat.country) {
      if (!threatsByCountry[threat.country]) {
        threatsByCountry[threat.country] = { count: 0, types: new Set(), severities: new Set() };
      }
      threatsByCountry[threat.country].count++;
      threatsByCountry[threat.country].types.add(threat.threat_type);
      threatsByCountry[threat.country].severities.add(threat.severity);
    }
  });

  return (
    <div className="h-[400px] w-full rounded-lg shadow-md overflow-hidden" data-testid="threat-map-container">
      <MapContainer center={[20, 0]} zoom={2} scrollWheelZoom={true} style={{ height: '100%', width: '100%' }}>
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
          url="https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png"
        />
        {Object.entries(threatsByCountry).map(([countryName, data]) => {
          const coord = countryCoordinates[countryName];
          if (!coord) {
            console.warn(`No coordinates found for country: ${countryName}`);
            return null;
          }

          // Scale marker radius by threat count, with min/max
          const radius = Math.max(5, Math.min(data.count * 2, 20));
          // Determine color by highest severity (simplified)
          let color = "blue"; // Default
          if (data.severities.has("High") || data.severities.has("Critical")) color = "red";
          else if (data.severities.has("Medium")) color = "orange";
          else if (data.severities.has("Low")) color = "green";


          return (
            <CircleMarker
              key={countryName}
              center={[coord.lat, coord.lng]}
              radius={radius}
              pathOptions={{ color, fillColor: color, fillOpacity: 0.7 }}
            >
              <Popup>
                <strong>{countryName}</strong>
                <br />
                Attacks: {data.count}
                <br />
                Types: {Array.from(data.types).join(', ')}
                <br />
                Severities: {Array.from(data.severities).join(', ')}
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>
    </div>
  );
};

export default ThreatMap;
