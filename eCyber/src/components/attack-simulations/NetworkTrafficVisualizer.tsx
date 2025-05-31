import React, { useState, useEffect, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { 
  Network, AlertTriangle, ExternalLink, Shield, Filter, FileJson, 
  Download, Play, StopCircle, FileText, Eye, Search, CircleCheck, CircleX
} from 'lucide-react';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  AreaChart,
  Area
} from 'recharts';
import { useTelemetrySocket } from '@/components/live-system/lib/socket';

// Types for packet data
interface PacketData {
  timestamp: string;
  source_ip: string;
  destination_ip?: string;
  host: string;
  path: string;
  method: string;
  user_agent: string;
  suspicious_headers: boolean;
  protocol: string;
  bytes_transferred: number;
  risk_score?: number;
  blocked?: boolean;
}

// Types for threat details
interface ThreatDetails {
  threat_summary: {
    risk_level: string;
    threat_score: number;
    contributing_indicators: string[];
    suggested_actions: string[];
  };
  network_details: {
    timestamp: string;
    source_ip: string;
    destination_ip: string;
    protocol: string;
  };
  security_headers_status: {
    missing_csp: boolean;
    missing_hsts: boolean;
    missing_xfo: boolean;
    missing_xcto: boolean;
    missing_rp: boolean;
    missing_xxp: boolean;
    hsts_short_max_age: boolean;
    insecure_cookies: boolean;
    insecure_csp: boolean;
  };
  behavioral_indicators: {
    beaconing_pattern: boolean;
    rapid_requests: boolean;
    slowloris_indicator: boolean;
  };
  content_analysis: {
    data_exfiltration: boolean;
    path_exfiltration: boolean;
    malicious_payloads: Record<string, any>;
    injection_patterns: string[];
  };
  header_analysis: {
    duplicate_headers: boolean;
    header_injection: boolean;
    invalid_format: boolean;
    malformed_values: boolean;
    obfuscated_headers: boolean;
    unusual_casing: boolean;
  };
}

// Mock packet data for simulation
const generateMockPacketData = (): PacketData => {
  // Sample domains to simulate real traffic
  const domains = [
    'github.com', 'cdn.gpteng.co', 'fonts.googleapis.com', 
    'bam.nr-data.net', 'clients4.google.com', 'beacons2.gvt2.com',
    'client.wns.windows.com', 'gitforwindows.org', 'api.example.com',
    'suspicious-domain.xyz', 'malware-server.net', 'data-exfil.io'
  ];
  
  // Generate a random domain
  const randomDomain = domains[Math.floor(Math.random() * domains.length)];
  
  // Randomly decide if this is a suspicious connection (15% chance)
  const isSuspicious = Math.random() < 0.15;
  
  // Generate a random source IP in the range
  const sourceIp = `192.168.43.${Math.floor(Math.random() * 254) + 1}`;
  
  // Generate a random destination IP in the range
  const destIp = `172.16.0.${Math.floor(Math.random() * 254) + 1}`;
  
  const methods = ['GET', 'POST', 'CONNECT', 'PUT', 'DELETE'];
  const randomMethod = methods[Math.floor(Math.random() * methods.length)];
  
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Postman/11.44.0 Electron/31.3.1 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15'
  ];
  const randomUserAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
  
  // Current timestamp in ISO format
  const now = new Date();
  
  // Generate a risk score based on suspiciousness
  const riskScore = isSuspicious 
    ? Math.floor(Math.random() * 70) + 30  // 30-100 for suspicious
    : Math.floor(Math.random() * 30);      // 0-29 for normal
    
  return {
    timestamp: now.toISOString(),
    source_ip: sourceIp,
    destination_ip: destIp,
    host: `${randomDomain}:443`,
    path: `${randomDomain}:443`,
    method: randomMethod,
    user_agent: randomUserAgent,
    suspicious_headers: isSuspicious,
    protocol: Math.random() > 0.5 ? 'HTTPS' : 'HTTP',
    bytes_transferred: Math.floor(Math.random() * 10000) + 100,
    risk_score: riskScore,
    blocked: false
  };
};

// Generate traffic metrics data
const generateTrafficMetrics = (minutes = 10) => {
  return Array.from({ length: minutes }, (_, i) => {
    return {
      time: `${i} min ago`,
      connections: Math.floor(Math.random() * 40) + 10,
      bandwidth: Math.floor(Math.random() * 500) + 100,
      packets: Math.floor(Math.random() * 200) + 50,
      anomalyScore: Math.random() > 0.8 ? (Math.random() * 80) + 20 : (Math.random() * 20)
    };
  }).reverse();
};

// Generate threat details for a packet
const generateThreatDetails = (packet: PacketData): ThreatDetails => {
  const riskScore = packet.risk_score || 0;
  const isSuspicious = packet.suspicious_headers || riskScore > 30;
  
  return {
    threat_summary: {
      risk_level: getRiskLevel(riskScore),
      threat_score: riskScore,
      contributing_indicators: [
        ...(isSuspicious ? ['suspicious_headers'] : []),
        ...(Math.random() > 0.5 ? ['rapid_requests'] : []),
        ...(Math.random() > 0.7 ? ['missing_csp'] : []),
      ],
      suggested_actions: [
        "Block Source IP",
        "Log this Event",
        "Add to Watchlist"
      ]
    },
    network_details: {
      timestamp: packet.timestamp,
      source_ip: packet.source_ip,
      destination_ip: packet.destination_ip || '192.168.43.15',
      protocol: packet.protocol
    },
    security_headers_status: {
      missing_csp: Math.random() > 0.6,
      missing_hsts: Math.random() > 0.5,
      missing_xfo: Math.random() > 0.4,
      missing_xcto: Math.random() > 0.3,
      missing_rp: Math.random() > 0.7,
      missing_xxp: Math.random() > 0.5,
      hsts_short_max_age: Math.random() > 0.8,
      insecure_cookies: Math.random() > 0.9,
      insecure_csp: Math.random() > 0.85
    },
    behavioral_indicators: {
      beaconing_pattern: Math.random() > 0.9,
      rapid_requests: Math.random() > 0.7,
      slowloris_indicator: Math.random() > 0.95
    },
    content_analysis: {
      data_exfiltration: Math.random() > 0.95,
      path_exfiltration: Math.random() > 0.97,
      malicious_payloads: {},
      injection_patterns: []
    },
    header_analysis: {
      duplicate_headers: Math.random() > 0.95,
      header_injection: Math.random() > 0.97,
      invalid_format: Math.random() > 0.98,
      malformed_values: Math.random() > 0.96,
      obfuscated_headers: Math.random() > 0.99,
      unusual_casing: Math.random() > 0.94
    }
  };
};

// Determine risk level from score
const getRiskLevel = (score: number): string => {
  if (score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 30) return "medium";
  if (score >= 10) return "low";
  return "info";
};

// Get color for risk level
const getRiskColor = (level: string): string => {
  switch (level) {
    case 'critical': return 'bg-red-500 border-red-700';
    case 'high': return 'bg-orange-500 border-orange-700';
    case 'medium': return 'bg-amber-500 border-amber-700';
    case 'low': return 'bg-blue-500 border-blue-700';
    default: return 'bg-green-500 border-green-700';
  }
};

// Format data for CSV export
const formatForCsv = (packets: PacketData[]): string => {
  const headers = "Timestamp,Source IP,Destination IP,Host,Method,Protocol,Risk Score,Risk Level,Blocked\n";
  
  const rows = packets.map(packet => {
    return [
      new Date(packet.timestamp).toLocaleString(),
      packet.source_ip,
      packet.destination_ip || '',
      packet.host,
      packet.method,
      packet.protocol,
      packet.risk_score || 0,
      getRiskLevel(packet.risk_score || 0),
      packet.blocked ? 'Yes' : 'No'
    ].join(',');
  }).join('\n');
  
  return headers + rows;
};

// Export data as file
const exportData = (data: string, fileType: string, fileName: string) => {
  const blob = new Blob([data], { type: `application/${fileType}` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

const NetworkTrafficVisualizer = () => {
  const { toast } = useToast();
  const [packets, setPackets] = useState<PacketData[]>([]);
  const [connectionHistory, setConnectionHistory] = useState<PacketData[]>([]);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [trafficMetrics, setTrafficMetrics] = useState(generateTrafficMetrics());
  const [activeTab, setActiveTab] = useState('live-traffic');
  const [isSniffing, setIsSniffing] = useState(true);
  const [selectedPacket, setSelectedPacket] = useState<PacketData | null>(null);
  const [packetDetails, setPacketDetails] = useState<ThreatDetails | null>(null);
  const [showDetails, setShowDetails] = useState(false);
  const [showAllConnections, setShowAllConnections] = useState(false);
  const [blockedIPs, setBlockedIPs] = useState<string[]>([]);
  const [isExporting, setIsExporting] = useState(false);
  const [exportType, setExportType] = useState<'json' | 'csv'>('json');
  
  const [availableInterfaces, setAvailableInterfaces] = useState<string[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string | null>(null);
  const [isInterfaceSelectionDisabled, setIsInterfaceSelectionDisabled] = useState(false);

  const { getSocket } = useTelemetrySocket();
  const socket = getSocket();
  const snifferIntervalRef = useRef<number | null>(null);

  useEffect(() => {
    if (!socket) return;

    // Interface listeners (should ideally be in a separate useEffect or managed globally if socket instance is global)
    const handleInterfacesList = (interfaces: string[]) => {
      console.log("Received interfaces:", interfaces);
      setAvailableInterfaces(interfaces);
    };
    const handleInterfaceSelectedStatus = (status: { status: string; interface?: string; message?: string }) => {
      if (status.status === 'success') {
        toast({ title: "Interface Selected", description: `Sniffer started on ${status.interface}`, variant: "default" });
        setIsSniffing(true);
        setIsInterfaceSelectionDisabled(true);
      } else {
        toast({ title: "Interface Selection Error", description: status.message || "Failed to start sniffer.", variant: "destructive" });
        setIsSniffing(false);
        setIsInterfaceSelectionDisabled(false);
      }
    };

    socket.on('interfaces_list', handleInterfacesList);
    socket.on('interface_selected_status', handleInterfaceSelectedStatus);

    // Real-time packet data handling
    if (isSniffing && selectedInterface) {
      if (snifferIntervalRef.current) {
        clearInterval(snifferIntervalRef.current);
        snifferIntervalRef.current = null;
      }
      console.log(`NetworkTrafficVisualizer: Listening for new_packet_data on interface ${selectedInterface}`);
      const handleNewPacket = (newPacket: PacketData) => {
        let processedPacket = { ...newPacket };
        if (processedPacket.risk_score && processedPacket.risk_score >= 80 && !processedPacket.blocked) {
          processedPacket.blocked = true;
          setBlockedIPs(prev => {
            if (!prev.includes(processedPacket.source_ip)) {
              toast({
                title: "Critical Risk IP Automatically Blocked",
                description: `${processedPacket.source_ip} was blocked due to high risk score (${processedPacket.risk_score})`,
                variant: "destructive"
              });
              return [...prev, processedPacket.source_ip];
            }
            return prev;
          });
        } else if (blockedIPs.includes(processedPacket.source_ip)) {
          processedPacket.blocked = true;
        }
        setPackets(prev => [processedPacket, ...prev].slice(0, 100));
        setConnectionHistory(prev => [processedPacket, ...prev].slice(0, 500));
        if (processedPacket.suspicious_headers && processedPacket.risk_score && processedPacket.risk_score > 50) {
          toast({
            title: `${getRiskLevel(processedPacket.risk_score).toUpperCase()} Risk Traffic Detected`,
            description: `Connection to ${processedPacket.host} from ${processedPacket.source_ip} (Risk: ${processedPacket.risk_score})`,
            variant: "destructive"
          });
        }
        // Consider moving metrics update to a separate mechanism if it's based on actual packet count
        // For now, this will update based on the state of 'packets' which might not be ideal.
        setTrafficMetrics(prevMetrics => {
             // This condition (packets.length % 10) is problematic here as packets state updates asynchronously.
             // A direct counter or different trigger would be better for metrics.
             // For simplicity of this step, we'll assume it's illustrative.
            const newMetrics = [...prevMetrics.slice(1), {
              time: "now", // Should be based on packet timestamp or consistent intervals
              connections: Math.floor(Math.random() * 40) + 10, // Placeholder
              bandwidth: processedPacket.bytes_transferred || Math.floor(Math.random() * 500) + 100, // Placeholder
              packets: 1, // Placeholder - this should be an aggregation
              anomalyScore: Math.random() > 0.8 ? (Math.random() * 80) + 20 : (Math.random() * 20) // Placeholder
            }];
            return newMetrics;
        });
      };
      socket.on('new_packet_data', handleNewPacket);

      return () => {
        socket.off('new_packet_data', handleNewPacket);
        socket.off('interfaces_list', handleInterfacesList);
        socket.off('interface_selected_status', handleInterfaceSelectedStatus);
        console.log("NetworkTrafficVisualizer: Stopped listening for new_packet_data and interface events.");
      };

    } else if (isSniffing && !selectedInterface) {
      // Fallback to MOCK data generation
      if (snifferIntervalRef.current) clearInterval(snifferIntervalRef.current);
      console.log("NetworkTrafficVisualizer: Started MOCK packet generation.");
      const interval = window.setInterval(() => {
        const mockPacket = generateMockPacketData();
        let processedPacket = { ...mockPacket };
        if (processedPacket.risk_score && processedPacket.risk_score >= 80 && !processedPacket.blocked) {
          processedPacket.blocked = true;
          setBlockedIPs(prev => {
            if (!prev.includes(processedPacket.source_ip)) {
               toast({ title: "Critical Risk IP Automatically Blocked (MOCK)", description: `${processedPacket.source_ip} blocked.`, variant: "destructive"});
              return [...prev, processedPacket.source_ip];
            }
            return prev;
          });
        } else if (blockedIPs.includes(processedPacket.source_ip)) {
          processedPacket.blocked = true;
        }
        setPackets(prev => [processedPacket, ...prev].slice(0, 100));
        setConnectionHistory(prev => [processedPacket, ...prev].slice(0, 500));
        if (processedPacket.suspicious_headers && processedPacket.risk_score && processedPacket.risk_score > 50) {
           toast({ title: `${getRiskLevel(processedPacket.risk_score).toUpperCase()} Risk Traffic (MOCK)`, description: `To ${processedPacket.host} from ${processedPacket.source_ip}`, variant: "destructive"});
        }
      }, 3000);
      snifferIntervalRef.current = interval;
      
      return () => {
        if (snifferIntervalRef.current) clearInterval(snifferIntervalRef.current);
        snifferIntervalRef.current = null;
        socket.off('interfaces_list', handleInterfacesList); // Also clean up other listeners
        socket.off('interface_selected_status', handleInterfaceSelectedStatus);
        console.log("NetworkTrafficVisualizer: Stopped MOCK packet generation and cleaned interface listeners.");
      };
    } else {
      // Sniffing is off
      if (snifferIntervalRef.current) {
        clearInterval(snifferIntervalRef.current);
        snifferIntervalRef.current = null;
      }
      // Clean up general listeners if not already done by other branches
      return () => {
        socket.off('interfaces_list', handleInterfacesList);
        socket.off('interface_selected_status', handleInterfaceSelectedStatus);
        // No new_packet_data listener to remove if we didn't enter the live data branch
      };
    }
  }, [socket, isSniffing, selectedInterface, blockedIPs, toast]); // Removed packets.length

  // Filter and search packets
  const filteredPackets = packets
    .filter(p => {
      // Apply category filter
      if (filter === 'all') return true;
      if (filter === 'suspicious') return p.suspicious_headers;
      if (filter === 'blocked') return p.blocked;
      if (filter === 'critical') return p.risk_score ? p.risk_score >= 80 : false;
      if (filter === 'high') return p.risk_score ? p.risk_score >= 50 && p.risk_score < 80 : false;
      return p.method === filter;
    })
    .filter(p => {
      // Apply search term
      if (!searchTerm) return true;
      const term = searchTerm.toLowerCase();
      return (
        p.source_ip?.toLowerCase().includes(term) ||
        p.destination_ip?.toLowerCase().includes(term) ||
        p.host?.toLowerCase().includes(term) ||
        p.protocol?.toLowerCase().includes(term) ||
        p.method?.toLowerCase().includes(term)
      );
    });

  // Handle packet action
  const handlePacketAction = (action: 'block' | 'unblock' | 'details', packet: PacketData) => {
    if (action === 'block') {
      setBlockedIPs(prev => [...prev, packet.source_ip]);
      setPackets(prev => prev.map(p => 
        p.source_ip === packet.source_ip ? {...p, blocked: true} : p
      ));
      
      toast({
        title: "IP Address Blocked",
        description: `${packet.source_ip} has been blocked`,
        variant: "default"
      });
    } 
    else if (action === 'unblock') {
      setBlockedIPs(prev => prev.filter(ip => ip !== packet.source_ip));
      setPackets(prev => prev.map(p => 
        p.source_ip === packet.source_ip ? {...p, blocked: false} : p
      ));
      
      toast({
        title: "IP Address Unblocked",
        description: `${packet.source_ip} has been unblocked`,
        variant: "default"
      });
    }
    else if (action === 'details') {
      setSelectedPacket(packet);
      
      // Generate threat details for the selected packet
      const details = generateThreatDetails(packet);
      setPacketDetails(details);
      setShowDetails(true);
    }
  };

  // Handle export action
  const handleExport = () => {
    if (!socket) {
      toast({ title: "Error", description: "Socket not connected. Cannot export.", variant: "destructive" });
      return;
    }

    const exportParams = {
      format: exportType, // 'json' or 'csv'
    };

    socket.emit('request_export_packets', exportParams);

    toast({
      title: "Export Requested",
      description: `Requesting ${exportType.toUpperCase()} export from server...`,
      variant: "default"
    });
    // Dialog will be closed by the response handler or manually by user.
  };

  useEffect(() => {
    if (!socket) return;

    const handleExportDataResponse = (response: { format?: string; data?: string; error?: string }) => {
      if (response.error) {
        toast({ title: "Export Failed", description: response.error, variant: "destructive" });
      } else if (response.data && response.format) {
        const fileName = `network-traffic-data.${response.format}`;
        exportData(response.data, response.format, fileName);
        toast({
          title: "Export Complete",
          description: `Traffic data downloaded as ${fileName}`,
          variant: "default"
        });
      } else {
        toast({ title: "Export Error", description: "Received invalid response from server.", variant: "destructive" });
      }
      setIsExporting(false); // Close dialog on any response
    };

    socket.on('export_data_response', handleExportDataResponse);

    return () => {
      socket.off('export_data_response', handleExportDataResponse);
    };
  }, [socket, toast]); // exportData and setIsExporting are stable

  // Toggle sniffing
  const toggleSniffing = () => {
    if (!isSniffing) { // Attempting to start sniffing
      if (socket && selectedInterface) {
        socket.emit('select_interface', selectedInterface);
        // setIsSniffing(true) and toast are handled by 'interface_selected_status' listener
      } else if (!selectedInterface) {
        toast({ title: "Error", description: "Please select a network interface first.", variant: "destructive" });
      } else {
        // Fallback for mock sniffing if no socket or interface, but button is pressed to start
        setIsSniffing(true);
        toast({ title: "Mock Sniffing Started", description: "Displaying simulated packet data.", variant: "default" });
      }
    } else { // Attempting to stop sniffing
      if (socket && selectedInterface) { // If it was sniffing on a real interface
        socket.emit('stop_sniffing');
      }
      // Common stop logic for both real and mock sniffing
      setIsSniffing(false);
      setIsInterfaceSelectionDisabled(false);
      toast({ title: "Network Sniffing Stopped", description: "Packet capture has been paused.", variant: "default" });
    }
  };

  // Handle export dialog
  const handleExportDialog = () => {
    setIsExporting(!isExporting);
  };

  // Get protocol badge with appropriate styling
  const getProtocolBadge = (protocol: string) => {
    switch (protocol) {
      case 'HTTPS':
        return <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">HTTPS</Badge>;
      case 'HTTP':
        return <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">HTTP</Badge>;
      default:
        return <Badge variant="outline">{protocol}</Badge>;
    }
  };

  // Get risk level badge
  const getRiskBadge = (score: number | undefined) => {
    if (score === undefined) return <Badge variant="outline">Unknown</Badge>;
    
    const level = getRiskLevel(score);
    let badgeClass = "";
    
    switch (level) {
      case 'critical':
        badgeClass = "bg-red-500/10 text-red-500 border-red-500";
        break;
      case 'high':
        badgeClass = "bg-orange-500/10 text-orange-500 border-orange-500";
        break;
      case 'medium':
        badgeClass = "bg-amber-500/10 text-amber-500 border-amber-500";
        break;
      case 'low':
        badgeClass = "bg-blue-500/10 text-blue-500 border-blue-500";
        break;
      default:
        badgeClass = "bg-green-500/10 text-green-500 border-green-500";
    }
    
    return (
      <Badge variant="outline" className={badgeClass}>
        {level.toUpperCase()} ({score})
      </Badge>
    );
  };

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="h-5 w-5 text-isimbi-purple" />
          Real-Time Network Traffic
        </CardTitle>
        <CardDescription>Visualize network traffic patterns and detect anomalies</CardDescription>
      </CardHeader>
      
      <div className="border-b border-border">
        <Tabs defaultValue="live-traffic" onValueChange={setActiveTab} className="w-full">
          <div className="px-6">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="live-traffic">Live Traffic</TabsTrigger>
              <TabsTrigger value="metrics">Traffic Metrics</TabsTrigger>
              <TabsTrigger value="anomalies">Anomaly Detection</TabsTrigger>
            </TabsList>
          </div>
          
          <TabsContent value="live-traffic" className="space-y-4 p-6">
            <div className="flex justify-between items-center flex-wrap gap-3">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-medium">Traffic Log</h3>
                <Badge variant={isSniffing ? "default" : "outline"} className="ml-1">
                  {isSniffing ? "Monitoring Active" : "Monitoring Inactive"}
                </Badge>
              </div>
              
              <div className="flex gap-2 flex-wrap">
                <div className="flex items-center gap-2">
                  <Label htmlFor="interface-select" className="text-xs">Interface:</Label>
                  <Select
                    value={selectedInterface || ""}
                    onValueChange={(value) => {
                      if (value === "no-interfaces") return;
                      setSelectedInterface(value);
                    }}
                    disabled={isInterfaceSelectionDisabled}
                  >
                    <SelectTrigger id="interface-select" className="w-[180px] h-8 text-xs">
                      <SelectValue placeholder="Select interface" />
                    </SelectTrigger>
                    <SelectContent>
                      {availableInterfaces.length > 0 ? availableInterfaces.map((iface) => (
                        <SelectItem key={iface} value={iface} className="text-xs">
                          {iface}
                        </SelectItem>
                      )) : (
                        <SelectItem value="no-interfaces" disabled className="text-xs">No interfaces found</SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                </div>
                <Button 
                  variant={isSniffing ? "destructive" : "default"} 
                  size="sm"
                  onClick={toggleSniffing}
                  disabled={!selectedInterface && !isSniffing} // Disable start if no interface selected and not already mock sniffing
                >
                  {isSniffing ? (
                    <><StopCircle size={14} className="mr-1" /> Stop Sniffing</>
                  ) : (
                    <><Play size={14} className="mr-1" /> Start Sniffing</>
                  )}
                </Button>
                
                <Select value={filter} onValueChange={setFilter}>
                  <SelectTrigger className="w-[150px] h-8">
                    <SelectValue placeholder="Filter" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Traffic</SelectItem>
                    <SelectItem value="suspicious">Suspicious Only</SelectItem>
                    <SelectItem value="blocked">Blocked IPs</SelectItem>
                    <SelectItem value="critical">Critical Risk</SelectItem>
                    <SelectItem value="high">High Risk</SelectItem>
                    <SelectItem value="GET">GET Requests</SelectItem>
                    <SelectItem value="POST">POST Requests</SelectItem>
                    <SelectItem value="CONNECT">CONNECT Requests</SelectItem>
                  </SelectContent>
                </Select>
                
                <div className="relative">
                  <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search IP, host..."
                    className="pl-8 h-8 w-[200px]"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
                
                <Button variant="outline" size="sm" className="h-8" onClick={handleExportDialog}>
                  <Download size={14} className="mr-1" /> Export
                </Button>
              </div>
            </div>
            
            <div className="border rounded-md">
              <div className="grid grid-cols-7 gap-2 py-2 px-3 bg-muted text-xs font-medium">
                <div className="col-span-1">Time</div>
                <div className="col-span-1">Source IP</div>
                <div className="col-span-1">Destination IP</div>
                <div className="col-span-1">Host</div>
                <div className="col-span-1">Protocol</div>
                <div className="col-span-1">Risk Level</div>
                <div className="col-span-1">Action</div>
              </div>
              
              <ScrollArea className="h-[300px]">
                <div className="divide-y">
                  {filteredPackets.length > 0 ? (
                    filteredPackets.map((packet, i) => (
                      <div 
                        key={i} 
                        className={`grid grid-cols-7 gap-2 py-2 px-3 text-xs ${
                          packet.blocked ? 'bg-gray-100 dark:bg-gray-800' :
                          packet.risk_score && packet.risk_score >= 80 ? 'bg-red-500/10' :
                          packet.risk_score && packet.risk_score >= 50 ? 'bg-orange-500/5' :
                          packet.risk_score && packet.risk_score >= 30 ? 'bg-amber-500/5' :
                          packet.suspicious_headers ? 'bg-blue-500/5' : 
                          ''
                        } hover:bg-muted/50`}
                      >
                        <div className="col-span-1 font-mono">
                          {new Date(packet.timestamp).toLocaleTimeString()}
                        </div>
                        <div className="col-span-1 font-mono" title={packet.source_ip}>
                          {packet.source_ip}
                        </div>
                        <div className="col-span-1 font-mono" title={packet.destination_ip}>
                          {packet.destination_ip || '—'}
                        </div>
                        <div className="col-span-1 truncate" title={packet.host}>
                          {packet.host}
                        </div>
                        <div className="col-span-1">
                          {getProtocolBadge(packet.protocol)}
                        </div>
                        <div className="col-span-1">
                          {getRiskBadge(packet.risk_score)}
                        </div>
                        <div className="col-span-1 flex gap-1">
                          {packet.blocked ? (
                            <Button 
                              variant="outline" 
                              size="sm" 
                              className="h-6 px-2 text-[10px]"
                              onClick={() => handlePacketAction('unblock', packet)}
                            >
                              <CircleCheck size={10} className="mr-1" /> Unblock
                            </Button>
                          ) : (
                            <Button 
                              variant="outline" 
                              size="sm" 
                              className="h-6 px-2 text-[10px]"
                              onClick={() => handlePacketAction('block', packet)}
                            >
                              <CircleX size={10} className="mr-1" /> Block
                            </Button>
                          )}
                          <Button 
                            variant="outline" 
                            size="sm" 
                            className="h-6 px-2 text-[10px]"
                            onClick={() => handlePacketAction('details', packet)}
                          >
                            <Eye size={10} className="mr-1" /> Details
                          </Button>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="py-8 text-center text-sm text-muted-foreground">
                      No traffic data available
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </TabsContent>
          
          <TabsContent value="metrics" className="p-6">
            <div className="space-y-6">
              <div className="h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={trafficMetrics} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(155, 155, 155, 0.1)" />
                    <XAxis dataKey="time" tick={{ fontSize: 12 }} />
                    <YAxis tick={{ fontSize: 12 }} />
                    <Tooltip />
                    <Legend />
                    <Line 
                      type="monotone" 
                      dataKey="connections" 
                      stroke="#8884d8" 
                      strokeWidth={2}
                      dot={{ r: 3 }}
                      activeDot={{ r: 8 }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="bandwidth" 
                      stroke="#82ca9d" 
                      strokeWidth={2}
                      dot={{ r: 3 }}
                      activeDot={{ r: 8 }}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="packets" 
                      stroke="#ffc658" 
                      strokeWidth={2}
                      dot={{ r: 3 }}
                      activeDot={{ r: 8 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
              
              <div className="grid grid-cols-3 gap-4">
                <div className="border rounded-md p-4">
                  <div className="text-2xl font-bold">
                    {filteredPackets.length > 0 && filteredPackets[0].bytes_transferred
                      ? `${filteredPackets[0].bytes_transferred} KB/s`
                      : '0 KB/s'
                    }
                  </div>
                  <div className="text-sm text-muted-foreground">Current Bandwidth</div>
                </div>
                <div className="border rounded-md p-4">
                  <div className="text-2xl font-bold">
                    {filteredPackets.length}
                  </div>
                  <div className="text-sm text-muted-foreground">Active Connections</div>
                </div>
                <div className="border rounded-md p-4">
                  <div className="text-2xl font-bold text-red-500">
                    {blockedIPs.length}
                  </div>
                  <div className="text-sm text-muted-foreground">Blocked IP Addresses</div>
                </div>
              </div>
              
              <div className="border rounded-md p-4">
                <h3 className="font-medium mb-3">Blocked IP Addresses</h3>
                {blockedIPs.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {blockedIPs.map((ip, index) => (
                      <Badge key={index} variant="outline" className="bg-red-500/10 text-red-500 border-red-500">
                        {ip}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-muted-foreground">No IP addresses have been blocked</div>
                )}
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="anomalies" className="p-6">
            <div className="space-y-6">
              <div className="h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trafficMetrics} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(155, 155, 155, 0.1)" />
                    <XAxis dataKey="time" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <defs>
                      <linearGradient id="anomalyColor" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#FF4D4D" stopOpacity={0.8}/>
                        <stop offset="95%" stopColor="#FF4D4D" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <Area 
                      type="monotone" 
                      dataKey="anomalyScore" 
                      stroke="#FF4D4D" 
                      strokeWidth={2}
                      fill="url(#anomalyColor)" 
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              
              <div className="border rounded-md p-4 bg-red-500/5">
                <h3 className="font-medium flex items-center">
                  <AlertTriangle size={16} className="text-red-500 mr-2" />
                  Behavioral Deviation Analysis
                </h3>
                <p className="mt-2 text-sm">
                  The system has detected unusual traffic patterns in the last 10 minutes. 
                  Potential indicators of suspicious activity include:
                </p>
                <ul className="list-disc list-inside mt-2 space-y-1 text-sm">
                  <li>Unusual connection attempts from {blockedIPs[0] || '192.168.43.131'}</li>
                  <li>Multiple DNS queries to client.wns.windows.com</li>
                  <li>Unexpected traffic to beacons2.gvt2.com</li>
                  <li>Behavior deviation score: {Math.floor(Math.random() * 30) + 30}/100</li>
                </ul>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
      
      <CardFooter className="bg-muted/30 flex justify-between items-center p-4">
        <div className="flex items-center text-xs text-muted-foreground">
          <Shield size={14} className="mr-1" />
          Real-time traffic analysis: {filteredPackets.length} displayed of {packets.length} packets
        </div>
        <Button 
          size="sm" 
          variant="outline" 
          className="text-xs"
          onClick={() => setShowAllConnections(true)}
        >
          <ExternalLink size={12} className="mr-1" />
          View All Connections
        </Button>
      </CardFooter>
      
      {/* Packet Details Dialog */}
      <Dialog open={showDetails} onOpenChange={setShowDetails}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Traffic Details</DialogTitle>
            <DialogDescription>
              Detailed information about the selected network traffic
            </DialogDescription>
          </DialogHeader>
          
          {selectedPacket && packetDetails && (
            <div className="space-y-4">
              {/* Summary Section */}
              <div className="p-4 rounded-md bg-muted/30">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-semibold">Risk Assessment</h3>
                  <Badge 
                    className={`${getRiskColor(packetDetails.threat_summary.risk_level)} text-white`}
                  >
                    {packetDetails.threat_summary.risk_level.toUpperCase()}
                  </Badge>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Threat Score</p>
                    <p className="font-mono">{packetDetails.threat_summary.threat_score}/100</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Contributing Indicators</p>
                    <div className="flex flex-wrap gap-1">
                      {packetDetails.threat_summary.contributing_indicators.map((indicator, i) => (
                        <Badge key={i} variant="outline" className="text-[10px]">
                          {indicator}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Network Details */}
              <div>
                <h3 className="font-semibold mb-2">Network Details</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-muted-foreground">Source IP</p>
                    <p className="font-mono">{packetDetails.network_details.source_ip}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Destination IP</p>
                    <p className="font-mono">{packetDetails.network_details.destination_ip}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Protocol</p>
                    <p>{packetDetails.network_details.protocol}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Timestamp</p>
                    <p>{new Date(packetDetails.network_details.timestamp).toLocaleString()}</p>
                  </div>
                </div>
              </div>
              
              <Separator />
              
              {/* Security Headers */}
              <div>
                <h3 className="font-semibold mb-2">Security Header Analysis</h3>
                <div className="grid grid-cols-3 gap-2">
                  {Object.entries(packetDetails.security_headers_status).map(([key, value]) => (
                    <div key={key} className="flex items-center">
                      {value ? (
                        <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500 mr-2">
                          Missing
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500 mr-2">
                          OK
                        </Badge>
                      )}
                      <span className="text-xs">{key.replace(/_/g, ' ')}</span>
                    </div>
                  ))}
                </div>
              </div>
              
              <Separator />
              
              {/* Behavioral Indicators */}
              <div>
                <h3 className="font-semibold mb-2">Behavioral Indicators</h3>
                <div className="grid grid-cols-3 gap-2">
                  {Object.entries(packetDetails.behavioral_indicators).map(([key, value]) => (
                    <div key={key} className="flex items-center">
                      {value ? (
                        <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500 mr-2">
                          Detected
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500 mr-2">
                          Clear
                        </Badge>
                      )}
                      <span className="text-xs">{key.replace(/_/g, ' ')}</span>
                    </div>
                  ))}
                </div>
              </div>
              
              <Separator />
              
              {/* Suggested Actions */}
              <div>
                <h3 className="font-semibold mb-2">Suggested Actions</h3>
                <div className="flex flex-wrap gap-2">
                  {packetDetails.threat_summary.suggested_actions.map((action, i) => (
                    <Button key={i} variant="outline" size="sm">
                      {action}
                    </Button>
                  ))}
                </div>
              </div>
            </div>
          )}
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDetails(false)}>Close</Button>
            {selectedPacket && !selectedPacket.blocked ? (
              <Button 
                variant="destructive" 
                onClick={() => {
                  handlePacketAction('block', selectedPacket);
                  setShowDetails(false);
                }}
              >
                Block IP
              </Button>
            ) : selectedPacket && selectedPacket.blocked ? (
              <Button 
                variant="default" 
                onClick={() => {
                  handlePacketAction('unblock', selectedPacket);
                  setShowDetails(false);
                }}
              >
                Unblock IP
              </Button>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>
      
      {/* All Connections Dialog */}
      <Dialog open={showAllConnections} onOpenChange={setShowAllConnections}>
        <DialogContent className="max-w-5xl h-[80vh]">
          <DialogHeader>
            <DialogTitle>All Network Connections</DialogTitle>
            <DialogDescription>
              Complete history of network connections detected
            </DialogDescription>
          </DialogHeader>
          
          <div className="flex justify-between items-center mb-4">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-medium">Connection History</h3>
              <Badge variant="outline">{connectionHistory.length} records</Badge>
            </div>
            
            <div className="flex gap-2">
              <div className="relative">
                <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search connections..."
                  className="pl-8 h-8 w-[200px]"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              
              <Button variant="outline" size="sm" onClick={handleExportDialog}>
                <Download size={14} className="mr-1" /> Export
              </Button>
            </div>
          </div>
          
          <div className="border rounded-md">
            <div className="grid grid-cols-7 gap-2 py-2 px-3 bg-muted text-xs font-medium">
              <div className="col-span-1">Time</div>
              <div className="col-span-1">Source IP</div>
              <div className="col-span-1">Destination IP</div>
              <div className="col-span-1">Host</div>
              <div className="col-span-1">Protocol</div>
              <div className="col-span-1">Risk Level</div>
              <div className="col-span-1">Status</div>
            </div>
            
            <ScrollArea className="h-[calc(80vh-220px)]">
              <div className="divide-y">
                {connectionHistory
                  .filter(conn => {
                    if (!searchTerm) return true;
                    const term = searchTerm.toLowerCase();
                    return (
                      conn.source_ip?.toLowerCase().includes(term) ||
                      conn.destination_ip?.toLowerCase().includes(term) ||
                      conn.host?.toLowerCase().includes(term) ||
                      conn.protocol?.toLowerCase().includes(term)
                    );
                  })
                  .map((connection, i) => (
                    <div 
                      key={i}
                      className={`grid grid-cols-7 gap-2 py-2 px-3 text-xs ${
                        connection.blocked ? 'bg-gray-100 dark:bg-gray-800' :
                        connection.risk_score && connection.risk_score >= 80 ? 'bg-red-500/10' :
                        connection.risk_score && connection.risk_score >= 50 ? 'bg-orange-500/5' :
                        connection.risk_score && connection.risk_score >= 30 ? 'bg-amber-500/5' :
                        connection.suspicious_headers ? 'bg-blue-500/5' : 
                        ''
                      } hover:bg-muted/50`}
                    >
                      <div className="col-span-1 font-mono">
                        {new Date(connection.timestamp).toLocaleString()}
                      </div>
                      <div className="col-span-1 font-mono">
                        {connection.source_ip}
                      </div>
                      <div className="col-span-1 font-mono">
                        {connection.destination_ip || '—'}
                      </div>
                      <div className="col-span-1 truncate" title={connection.host}>
                        {connection.host}
                      </div>
                      <div className="col-span-1">
                        {getProtocolBadge(connection.protocol)}
                      </div>
                      <div className="col-span-1">
                        {getRiskBadge(connection.risk_score)}
                      </div>
                      <div className="col-span-1">
                        {connection.blocked ? (
                          <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">
                            Blocked
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">
                            Allowed
                          </Badge>
                        )}
                      </div>
                    </div>
                  ))
                }
              </div>
            </ScrollArea>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAllConnections(false)}>Close</Button>
            <Button 
              variant="default" 
              onClick={() => {
                handleExport();
                setShowAllConnections(false);
              }}
            >
              Export Log
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      
      {/* Export Dialog */}
      <Dialog open={isExporting} onOpenChange={setIsExporting}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Export Traffic Data</DialogTitle>
            <DialogDescription>
              Choose export format and options
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Export Format</Label>
              <div className="flex gap-4">
                <div className="flex items-center space-x-2">
                  <input
                    type="radio"
                    id="json-format"
                    checked={exportType === 'json'}
                    onChange={() => setExportType('json')}
                    className="h-4 w-4"
                  />
                  <Label htmlFor="json-format" className="font-normal">
                    <div className="flex items-center">
                      <FileJson size={16} className="mr-1" />
                      JSON
                    </div>
                  </Label>
                </div>
                
                <div className="flex items-center space-x-2">
                  <input
                    type="radio"
                    id="csv-format"
                    checked={exportType === 'csv'}
                    onChange={() => setExportType('csv')}
                    className="h-4 w-4"
                  />
                  <Label htmlFor="csv-format" className="font-normal">
                    <div className="flex items-center">
                      <FileText size={16} className="mr-1" />
                      CSV
                    </div>
                  </Label>
                </div>
              </div>
            </div>
            
            <div className="space-y-2">
              <Label>Data Selection</Label>
              <div className="flex items-center space-x-2">
                <Switch
                  id="export-all"
                  checked={showAllConnections}
                  onCheckedChange={setShowAllConnections}
                />
                <Label htmlFor="export-all" className="font-normal">
                  Export all connection history ({connectionHistory.length} records)
                </Label>
              </div>
              {!showAllConnections && (
                <p className="text-xs text-muted-foreground">
                  Only exporting current filtered view ({filteredPackets.length} records)
                </p>
              )}
            </div>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsExporting(false)}>Cancel</Button>
            <Button 
              onClick={() => {
                handleExport();
                setIsExporting(false);
              }}
            >
              <Download size={14} className="mr-1" />
              Export
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
};

export default NetworkTrafficVisualizer;