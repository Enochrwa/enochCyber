import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import ThreatMap from './ThreatMap'; // Adjust path as necessary
import apiClient from '../../lib/apiClient';

// Mock the apiClient
jest.mock('../../lib/apiClient');
const mockedApiClient = apiClient as jest.Mocked<typeof apiClient>;

// Mock Leaflet's map container rendering as it relies on browser APIs not available in JSDOM
// A more sophisticated mock might be needed for deeper testing, but this handles basic rendering.
jest.mock('react-leaflet', () => ({
  ...jest.requireActual('react-leaflet'), // Import and retain default exports
  MapContainer: ({ children }: { children: React.ReactNode }) => <div data-testid="map-container">{children}</div>,
  TileLayer: () => <div data-testid="tile-layer">Tile Layer</div>,
  CircleMarker: ({ children }: { children: React.ReactNode }) => <div data-testid="circle-marker">{children}</div>,
  Popup: ({ children }: { children: React.ReactNode }) => <div data-testid="popup">{children}</div>,
}));


describe('ThreatMap Component', () => {
  beforeEach(() => {
    // Reset any previous mock implementation before each test
    mockedApiClient.get.mockReset();
  });

  it('renders loading state initially', () => {
    mockedApiClient.get.mockImplementation(() => new Promise(() => {})); // Pending promise to keep it loading
    render(<ThreatMap />);
    expect(screen.getByText(/loading map data.../i)).toBeInTheDocument();
  });

  it('renders map container and tile layer on successful data fetch (even with empty data)', async () => {
    mockedApiClient.get.mockResolvedValueOnce({ data: [] }); // Mock successful empty response
    render(<ThreatMap />);

    await waitFor(() => {
      // Check for the Leaflet map container mock
      expect(screen.getByTestId('map-container')).toBeInTheDocument();
    });
    // Check for the TileLayer mock (might appear immediately or after data load)
    expect(screen.getByTestId('tile-layer')).toBeInTheDocument();
    // With empty data, it should show no data message
    expect(screen.getByText(/no geolocated threat data available./i)).toBeInTheDocument();
  });

  it('displays markers when threat data is available', async () => {
    const mockThreats = [
      {
        source_ip: '1.2.3.4',
        latitude: null,
        longitude: null,
        city: null,
        country: 'United States',
        timestamp: new Date().toISOString(),
        threat_type: 'Test Threat',
        severity: 'High',
      },
      {
        source_ip: '5.6.7.8',
        latitude: null,
        longitude: null,
        city: null,
        country: 'China',
        timestamp: new Date().toISOString(),
        threat_type: 'Another Threat',
        severity: 'Medium',
      },
    ];
    mockedApiClient.get.mockResolvedValueOnce({ data: mockThreats });

    render(<ThreatMap />);

    // Wait for the markers to be rendered
    // Since we aggregate by country, we expect 2 markers for 2 unique countries
    await waitFor(() => {
      expect(screen.getAllByTestId('circle-marker')).toHaveLength(2);
    });
    expect(screen.getAllByTestId('popup')).toHaveLength(2); // Each marker should have a popup
  });

  it('displays an error message when API call fails', async () => {
    mockedApiClient.get.mockRejectedValueOnce(new Error('Failed to fetch'));
    render(<ThreatMap />);

    await waitFor(() => {
      expect(screen.getByText(/failed to load threat data for map./i)).toBeInTheDocument();
    });
  });

  it('renders the main map container div', async () => {
    mockedApiClient.get.mockResolvedValueOnce({ data: [] });
    render(<ThreatMap />);
    await waitFor(() => {
        // This testid is on the component's root div
        expect(screen.getByTestId('threat-map-container')).toBeInTheDocument();
    });
  });

});
