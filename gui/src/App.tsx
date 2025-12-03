import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Shield,
  ShieldOff,
  Settings,
  Server,
  CreditCard,
  ChevronRight,
  Loader2,
  Check,
  X,
  Globe,
  Zap,
  Users,
  Wifi,
  RefreshCw,
  Link,
} from "lucide-react";

type ConnectionState = "disconnected" | "connecting" | "connected" | "disconnecting" | "error";

interface ServerInfo {
  id: string;
  name: string;
  country: string;
  city: string;
  load: number;
  latency_ms: number | null;
  is_premium: boolean;
}

interface ConnectionStats {
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  connected_since: number | null;
  uptime_secs: number;
  current_server: string | null;
}

interface CommandResult<T> {
  success: boolean;
  data: T | null;
  error: string | null;
}

interface NatDetectionResult {
  nat_type: string;
  public_ip: string | null;
  public_port: number | null;
  description: string;
}

interface P2PPeerInfo {
  peer_id: string;
  public_addr: string;
  nat_type: string;
  last_seen: number;
  can_relay: boolean;
}

interface P2PConnectionResult {
  success: boolean;
  method: string;
  peer_addr: string;
  latency_ms: number;
}

interface RelayConnectionResult {
  success: boolean;
  relay_addr: string;
  message: string;
}

function App() {
  const [status, setStatus] = useState<ConnectionState>("disconnected");
  const [stats, setStats] = useState<ConnectionStats | null>(null);
  const [servers, setServers] = useState<ServerInfo[]>([]);
  const [selectedServer, setSelectedServer] = useState<ServerInfo | null>(null);
  const [view, setView] = useState<"main" | "servers" | "settings" | "subscription" | "p2p">("main");
  const [isLoading, setIsLoading] = useState(false);

  // P2P state
  const [natInfo, setNatInfo] = useState<NatDetectionResult | null>(null);
  const [peers, setPeers] = useState<P2PPeerInfo[]>([]);
  const [p2pStatus, setP2pStatus] = useState<string>("");
  const [p2pLoading, setP2pLoading] = useState(false);

  // Fetch initial data
  useEffect(() => {
    loadData();
    const interval = setInterval(updateStats, 1000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const statusResult = await invoke<CommandResult<ConnectionState>>("get_status");
      if (statusResult.success && statusResult.data) {
        setStatus(statusResult.data);
      }

      const serversResult = await invoke<CommandResult<ServerInfo[]>>("get_servers");
      if (serversResult.success && serversResult.data) {
        setServers(serversResult.data);
        setSelectedServer(serversResult.data[0] || null);
      }
    } catch (e) {
      console.error("Failed to load data:", e);
    }
  };

  const updateStats = async () => {
    try {
      const result = await invoke<CommandResult<ConnectionStats>>("get_stats");
      if (result.success && result.data) {
        setStats(result.data);
      }

      const statusResult = await invoke<CommandResult<ConnectionState>>("get_status");
      if (statusResult.success && statusResult.data) {
        setStatus(statusResult.data);
      }
    } catch (e) {
      console.error("Failed to update stats:", e);
    }
  };

  const handleConnect = async () => {
    setIsLoading(true);
    try {
      const result = await invoke<CommandResult<string>>("connect");
      if (!result.success) {
        console.error("Connect failed:", result.error);
      }
    } catch (e) {
      console.error("Connect error:", e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisconnect = async () => {
    setIsLoading(true);
    try {
      const result = await invoke<CommandResult<string>>("disconnect");
      if (!result.success) {
        console.error("Disconnect failed:", result.error);
      }
    } catch (e) {
      console.error("Disconnect error:", e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleServerSelect = async (server: ServerInfo) => {
    try {
      const result = await invoke<CommandResult<ServerInfo>>("set_server", { serverId: server.id });
      if (result.success && result.data) {
        setSelectedServer(result.data);
      }
    } catch (e) {
      console.error("Failed to set server:", e);
    }
    setView("main");
  };

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const formatDuration = (secs: number): string => {
    const hours = Math.floor(secs / 3600);
    const minutes = Math.floor((secs % 3600) / 60);
    const seconds = secs % 60;
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
  };

  // P2P Functions
  const handleDetectNat = async () => {
    setP2pLoading(true);
    setP2pStatus("Detecting NAT type...");
    try {
      const result = await invoke<CommandResult<NatDetectionResult>>("detect_nat");
      if (result.success && result.data) {
        setNatInfo(result.data);
        setP2pStatus(`NAT: ${result.data.nat_type} - ${result.data.description}`);
      } else {
        setP2pStatus(`Error: ${result.error}`);
      }
    } catch (e) {
      setP2pStatus(`Error: ${e}`);
    } finally {
      setP2pLoading(false);
    }
  };

  const handleRegisterP2p = async () => {
    setP2pLoading(true);
    setP2pStatus("Registering with discovery server...");
    try {
      const result = await invoke<CommandResult<string>>("register_p2p");
      if (result.success && result.data) {
        setP2pStatus(result.data);
      } else {
        setP2pStatus(`Error: ${result.error}`);
      }
    } catch (e) {
      setP2pStatus(`Error: ${e}`);
    } finally {
      setP2pLoading(false);
    }
  };

  const handleDiscoverPeers = async () => {
    setP2pLoading(true);
    setP2pStatus("Discovering peers...");
    try {
      const result = await invoke<CommandResult<P2PPeerInfo[]>>("discover_peers");
      if (result.success && result.data) {
        setPeers(result.data);
        setP2pStatus(`Found ${result.data.length} peers`);
      } else {
        setP2pStatus(`Error: ${result.error}`);
      }
    } catch (e) {
      setP2pStatus(`Error: ${e}`);
    } finally {
      setP2pLoading(false);
    }
  };

  const handleConnectPeer = async (peerId: string) => {
    setP2pLoading(true);
    setP2pStatus(`Connecting to peer ${peerId}...`);
    try {
      const result = await invoke<CommandResult<P2PConnectionResult>>("connect_peer", { peerIdHex: peerId });
      if (result.success && result.data) {
        setP2pStatus(`Connected to ${result.data.peer_addr} via ${result.data.method} (${result.data.latency_ms}ms)`);
      } else {
        setP2pStatus(`Error: ${result.error}`);
      }
    } catch (e) {
      setP2pStatus(`Error: ${e}`);
    } finally {
      setP2pLoading(false);
    }
  };

  const handleConnectViaRelay = async (peerId: string) => {
    setP2pLoading(true);
    setP2pStatus(`Connecting to peer ${peerId} via relay...`);
    try {
      const result = await invoke<CommandResult<RelayConnectionResult>>("connect_via_relay", { peerIdHex: peerId });
      if (result.success && result.data) {
        setP2pStatus(`${result.data.message}`);
      } else {
        setP2pStatus(`Error: ${result.error}`);
      }
    } catch (e) {
      setP2pStatus(`Error: ${e}`);
    } finally {
      setP2pLoading(false);
    }
  };

  const formatNatType = (natType: string): string => {
    const types: Record<string, string> = {
      none: "No NAT",
      full_cone: "Full Cone",
      address_restricted: "Address Restricted",
      port_restricted: "Port Restricted",
      symmetric: "Symmetric",
      unknown: "Unknown",
    };
    return types[natType] || natType;
  };

  const isConnected = status === "connected";
  const isConnecting = status === "connecting" || status === "disconnecting";

  // Main view
  if (view === "main") {
    return (
      <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 text-white">
        <div className="container mx-auto px-4 py-6 max-w-md">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center space-x-2">
              <Shield className="w-8 h-8 text-green-400" />
              <span className="text-xl font-bold">MeshVPN</span>
            </div>
            <button
              onClick={() => setView("settings")}
              className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
            >
              <Settings className="w-5 h-5" />
            </button>
          </div>

          {/* Connection Status */}
          <div className="text-center mb-8">
            <div
              className={`inline-flex items-center justify-center w-32 h-32 rounded-full mb-4 transition-all duration-300 ${
                isConnected
                  ? "bg-green-500/20 ring-4 ring-green-500/50"
                  : "bg-slate-700"
              }`}
            >
              {isConnecting ? (
                <Loader2 className="w-16 h-16 text-blue-400 animate-spin" />
              ) : isConnected ? (
                <Shield className="w-16 h-16 text-green-400" />
              ) : (
                <ShieldOff className="w-16 h-16 text-slate-400" />
              )}
            </div>

            <h2 className="text-2xl font-semibold mb-2">
              {status === "connected" && "Protected"}
              {status === "connecting" && "Connecting..."}
              {status === "disconnecting" && "Disconnecting..."}
              {status === "disconnected" && "Not Protected"}
              {status === "error" && "Connection Error"}
            </h2>

            {isConnected && stats && (
              <p className="text-slate-400">
                Connected for {formatDuration(stats.uptime_secs)}
              </p>
            )}
          </div>

          {/* Server Selection */}
          <button
            onClick={() => setView("servers")}
            className="w-full flex items-center justify-between p-4 bg-slate-700/50 rounded-xl mb-4 hover:bg-slate-700 transition-colors"
          >
            <div className="flex items-center space-x-3">
              <Globe className="w-5 h-5 text-blue-400" />
              <div className="text-left">
                <div className="font-medium">
                  {selectedServer?.name || "Select Server"}
                </div>
                <div className="text-sm text-slate-400">
                  {selectedServer?.country} • {selectedServer?.city}
                </div>
              </div>
            </div>
            <ChevronRight className="w-5 h-5 text-slate-400" />
          </button>

          {/* Connect Button */}
          <button
            onClick={isConnected ? handleDisconnect : handleConnect}
            disabled={isConnecting || isLoading}
            className={`w-full py-4 rounded-xl font-semibold text-lg transition-all duration-300 ${
              isConnected
                ? "bg-red-500 hover:bg-red-600"
                : "bg-green-500 hover:bg-green-600"
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            {isLoading ? (
              <Loader2 className="w-6 h-6 mx-auto animate-spin" />
            ) : isConnected ? (
              "Disconnect"
            ) : (
              "Connect"
            )}
          </button>

          {/* Stats */}
          {isConnected && stats && (
            <div className="grid grid-cols-2 gap-4 mt-6">
              <div className="bg-slate-700/50 rounded-xl p-4">
                <div className="text-slate-400 text-sm mb-1">Download</div>
                <div className="text-xl font-semibold">
                  {formatBytes(stats.bytes_received)}
                </div>
              </div>
              <div className="bg-slate-700/50 rounded-xl p-4">
                <div className="text-slate-400 text-sm mb-1">Upload</div>
                <div className="text-xl font-semibold">
                  {formatBytes(stats.bytes_sent)}
                </div>
              </div>
            </div>
          )}

          {/* Bottom Navigation */}
          <div className="fixed bottom-0 left-0 right-0 bg-slate-800 border-t border-slate-700">
            <div className="flex justify-around py-3 max-w-md mx-auto">
              <button
                onClick={() => setView("main")}
                className="flex flex-col items-center text-green-400"
              >
                <Shield className="w-6 h-6" />
                <span className="text-xs mt-1">VPN</span>
              </button>
              <button
                onClick={() => setView("servers")}
                className="flex flex-col items-center text-slate-400 hover:text-white"
              >
                <Server className="w-6 h-6" />
                <span className="text-xs mt-1">Servers</span>
              </button>
              <button
                onClick={() => setView("p2p")}
                className="flex flex-col items-center text-slate-400 hover:text-white"
              >
                <Users className="w-6 h-6" />
                <span className="text-xs mt-1">P2P</span>
              </button>
              <button
                onClick={() => setView("subscription")}
                className="flex flex-col items-center text-slate-400 hover:text-white"
              >
                <CreditCard className="w-6 h-6" />
                <span className="text-xs mt-1">Plan</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Servers view
  if (view === "servers") {
    return (
      <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 text-white">
        <div className="container mx-auto px-4 py-6 max-w-md">
          <div className="flex items-center mb-6">
            <button
              onClick={() => setView("main")}
              className="p-2 hover:bg-slate-700 rounded-lg mr-2"
            >
              <X className="w-5 h-5" />
            </button>
            <h1 className="text-xl font-bold">Select Server</h1>
          </div>

          <div className="space-y-3 pb-20">
            {servers.map((server) => (
              <button
                key={server.id}
                onClick={() => handleServerSelect(server)}
                className={`w-full flex items-center justify-between p-4 rounded-xl transition-colors ${
                  selectedServer?.id === server.id
                    ? "bg-green-500/20 border border-green-500"
                    : "bg-slate-700/50 hover:bg-slate-700"
                }`}
              >
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-slate-600 rounded-full flex items-center justify-center">
                    <Globe className="w-5 h-5" />
                  </div>
                  <div className="text-left">
                    <div className="font-medium flex items-center">
                      {server.name}
                      {server.is_premium && (
                        <Zap className="w-4 h-4 text-yellow-400 ml-2" />
                      )}
                    </div>
                    <div className="text-sm text-slate-400">
                      {server.country} • {server.city}
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div
                    className={`text-sm ${
                      server.load < 50
                        ? "text-green-400"
                        : server.load < 80
                        ? "text-yellow-400"
                        : "text-red-400"
                    }`}
                  >
                    {server.load}% load
                  </div>
                  {server.latency_ms && (
                    <div className="text-xs text-slate-400">
                      {server.latency_ms}ms
                    </div>
                  )}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Settings view
  if (view === "settings") {
    return (
      <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 text-white">
        <div className="container mx-auto px-4 py-6 max-w-md">
          <div className="flex items-center mb-6">
            <button
              onClick={() => setView("main")}
              className="p-2 hover:bg-slate-700 rounded-lg mr-2"
            >
              <X className="w-5 h-5" />
            </button>
            <h1 className="text-xl font-bold">Settings</h1>
          </div>

          <div className="space-y-4">
            <div className="bg-slate-700/50 rounded-xl p-4">
              <h3 className="font-semibold mb-3">Connection</h3>
              <div className="space-y-3">
                <label className="flex items-center justify-between">
                  <span>Auto-connect on startup</span>
                  <input type="checkbox" className="w-5 h-5 rounded" />
                </label>
                <label className="flex items-center justify-between">
                  <span>Kill switch</span>
                  <input type="checkbox" className="w-5 h-5 rounded" />
                </label>
              </div>
            </div>

            <div className="bg-slate-700/50 rounded-xl p-4">
              <h3 className="font-semibold mb-3">Appearance</h3>
              <div className="space-y-3">
                <label className="flex items-center justify-between">
                  <span>Start minimized</span>
                  <input type="checkbox" className="w-5 h-5 rounded" />
                </label>
                <label className="flex items-center justify-between">
                  <span>Show notifications</span>
                  <input type="checkbox" className="w-5 h-5 rounded" defaultChecked />
                </label>
              </div>
            </div>

            <div className="bg-slate-700/50 rounded-xl p-4">
              <h3 className="font-semibold mb-3">Identity</h3>
              <p className="text-sm text-slate-400 mb-3">
                Your cryptographic identity for the mesh network
              </p>
              <div className="space-y-2">
                <button className="w-full py-2 bg-slate-600 rounded-lg hover:bg-slate-500 transition-colors">
                  Export Identity
                </button>
                <button className="w-full py-2 bg-slate-600 rounded-lg hover:bg-slate-500 transition-colors">
                  Import Identity
                </button>
              </div>
            </div>

            <div className="bg-slate-700/50 rounded-xl p-4">
              <h3 className="font-semibold mb-3">About</h3>
              <div className="text-sm text-slate-400 space-y-1">
                <p>MeshVPN v0.1.0</p>
                <p>Decentralized VPN with onion routing</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Subscription view
  if (view === "subscription") {
    return (
      <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 text-white">
        <div className="container mx-auto px-4 py-6 max-w-md pb-20">
          <div className="flex items-center mb-6">
            <button
              onClick={() => setView("main")}
              className="p-2 hover:bg-slate-700 rounded-lg mr-2"
            >
              <X className="w-5 h-5" />
            </button>
            <h1 className="text-xl font-bold">Subscription</h1>
          </div>

          <div className="bg-slate-700/50 rounded-xl p-4 mb-6">
            <div className="flex items-center justify-between mb-2">
              <span className="text-slate-400">Current Plan</span>
              <span className="bg-slate-600 px-2 py-1 rounded text-sm">Free</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Data Used</span>
              <span>2.1 GB / 5 GB</span>
            </div>
          </div>

          <h2 className="text-lg font-semibold mb-4">Upgrade Your Plan</h2>
          <p className="text-slate-400 text-sm mb-4">
            Pay with Monero (XMR) for anonymous subscriptions
          </p>

          <div className="space-y-4">
            <div className="bg-slate-700/50 rounded-xl p-4 border border-transparent hover:border-green-500 transition-colors cursor-pointer">
              <div className="flex justify-between items-start mb-2">
                <div>
                  <h3 className="font-semibold">Basic</h3>
                  <p className="text-sm text-slate-400">50 GB/month</p>
                </div>
                <div className="text-right">
                  <div className="font-bold">0.05 XMR</div>
                  <div className="text-sm text-slate-400">/month</div>
                </div>
              </div>
              <ul className="text-sm text-slate-400 space-y-1">
                <li className="flex items-center">
                  <Check className="w-4 h-4 text-green-400 mr-2" />
                  All server locations
                </li>
                <li className="flex items-center">
                  <Check className="w-4 h-4 text-green-400 mr-2" />
                  3 devices
                </li>
              </ul>
            </div>

            <div className="bg-slate-700/50 rounded-xl p-4 border-2 border-green-500 cursor-pointer">
              <div className="flex justify-between items-start mb-2">
                <div>
                  <h3 className="font-semibold flex items-center">
                    Premium
                    <span className="ml-2 bg-green-500 text-xs px-2 py-0.5 rounded">POPULAR</span>
                  </h3>
                  <p className="text-sm text-slate-400">200 GB/month</p>
                </div>
                <div className="text-right">
                  <div className="font-bold">0.15 XMR</div>
                  <div className="text-sm text-slate-400">/month</div>
                </div>
              </div>
              <ul className="text-sm text-slate-400 space-y-1">
                <li className="flex items-center">
                  <Check className="w-4 h-4 text-green-400 mr-2" />
                  All server locations
                </li>
                <li className="flex items-center">
                  <Check className="w-4 h-4 text-green-400 mr-2" />
                  10 devices
                </li>
                <li className="flex items-center">
                  <Check className="w-4 h-4 text-green-400 mr-2" />
                  Priority support
                </li>
              </ul>
            </div>

            <div className="bg-slate-700/50 rounded-xl p-4 border border-transparent hover:border-green-500 transition-colors cursor-pointer">
              <div className="flex justify-between items-start mb-2">
                <div>
                  <h3 className="font-semibold flex items-center">
                    Unlimited
                    <Zap className="w-4 h-4 text-yellow-400 ml-2" />
                  </h3>
                  <p className="text-sm text-slate-400">No limits</p>
                </div>
                <div className="text-right">
                  <div className="font-bold">0.30 XMR</div>
                  <div className="text-sm text-slate-400">/month</div>
                </div>
              </div>
              <ul className="text-sm text-slate-400 space-y-1">
                <li className="flex items-center">
                  <Check className="w-4 h-4 text-green-400 mr-2" />
                  Unlimited data
                </li>
                <li className="flex items-center">
                  <Check className="w-4 h-4 text-green-400 mr-2" />
                  Unlimited devices
                </li>
                <li className="flex items-center">
                  <Check className="w-4 h-4 text-green-400 mr-2" />
                  Dedicated exit nodes
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // P2P view
  if (view === "p2p") {
    return (
      <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 text-white">
        <div className="container mx-auto px-4 py-6 max-w-md pb-20">
          <div className="flex items-center mb-6">
            <button
              onClick={() => setView("main")}
              className="p-2 hover:bg-slate-700 rounded-lg mr-2"
            >
              <X className="w-5 h-5" />
            </button>
            <h1 className="text-xl font-bold">P2P Network</h1>
          </div>

          {/* Status */}
          {p2pStatus && (
            <div className="bg-slate-700/50 rounded-xl p-4 mb-4">
              <div className="flex items-center space-x-2">
                {p2pLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                <span className="text-sm">{p2pStatus}</span>
              </div>
            </div>
          )}

          {/* NAT Info */}
          <div className="bg-slate-700/50 rounded-xl p-4 mb-4">
            <h3 className="font-semibold mb-3 flex items-center">
              <Wifi className="w-5 h-5 mr-2 text-blue-400" />
              NAT Detection
            </h3>
            {natInfo ? (
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-400">NAT Type:</span>
                  <span className={`font-medium ${
                    natInfo.nat_type === "full_cone" ? "text-green-400" :
                    natInfo.nat_type === "symmetric" ? "text-red-400" : "text-yellow-400"
                  }`}>
                    {formatNatType(natInfo.nat_type)}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Public IP:</span>
                  <span>{natInfo.public_ip || "Unknown"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Public Port:</span>
                  <span>{natInfo.public_port || "Unknown"}</span>
                </div>
                <p className="text-slate-400 text-xs mt-2">{natInfo.description}</p>
              </div>
            ) : (
              <p className="text-slate-400 text-sm">Click "Detect NAT" to analyze your network</p>
            )}
            <button
              onClick={handleDetectNat}
              disabled={p2pLoading}
              className="w-full mt-3 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg transition-colors disabled:opacity-50"
            >
              {p2pLoading ? <Loader2 className="w-4 h-4 mx-auto animate-spin" /> : "Detect NAT"}
            </button>
          </div>

          {/* Registration */}
          <div className="bg-slate-700/50 rounded-xl p-4 mb-4">
            <h3 className="font-semibold mb-3 flex items-center">
              <Link className="w-5 h-5 mr-2 text-green-400" />
              Discovery Server
            </h3>
            <p className="text-slate-400 text-sm mb-3">
              Register with the P2P discovery server to allow other peers to find you.
            </p>
            <button
              onClick={handleRegisterP2p}
              disabled={p2pLoading}
              className="w-full py-2 bg-green-500 hover:bg-green-600 rounded-lg transition-colors disabled:opacity-50"
            >
              {p2pLoading ? <Loader2 className="w-4 h-4 mx-auto animate-spin" /> : "Register"}
            </button>
          </div>

          {/* Peer Discovery */}
          <div className="bg-slate-700/50 rounded-xl p-4 mb-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold flex items-center">
                <Users className="w-5 h-5 mr-2 text-purple-400" />
                Discovered Peers
              </h3>
              <button
                onClick={handleDiscoverPeers}
                disabled={p2pLoading}
                className="p-2 hover:bg-slate-600 rounded-lg transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${p2pLoading ? "animate-spin" : ""}`} />
              </button>
            </div>

            {peers.length > 0 ? (
              <div className="space-y-2">
                {peers.map((peer) => (
                  <div
                    key={peer.peer_id}
                    className="bg-slate-600/50 rounded-lg p-3"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <div className="font-mono text-sm">{peer.peer_id.substring(0, 16)}</div>
                        <div className="text-xs text-slate-400">
                          {peer.public_addr} • {formatNatType(peer.nat_type)}
                          {peer.can_relay && " • Relay"}
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleConnectPeer(peer.peer_id)}
                        disabled={p2pLoading}
                        className="flex-1 px-3 py-1 bg-purple-500 hover:bg-purple-600 rounded text-sm transition-colors disabled:opacity-50"
                      >
                        Direct
                      </button>
                      {(peer.nat_type === "symmetric" || natInfo?.nat_type === "symmetric") && (
                        <button
                          onClick={() => handleConnectViaRelay(peer.peer_id)}
                          disabled={p2pLoading}
                          className="flex-1 px-3 py-1 bg-orange-500 hover:bg-orange-600 rounded text-sm transition-colors disabled:opacity-50"
                        >
                          Via Relay
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-slate-400 text-sm">
                No peers discovered. Click refresh to search for peers.
              </p>
            )}
          </div>

          {/* Info */}
          <div className="bg-slate-700/50 rounded-xl p-4">
            <h3 className="font-semibold mb-2">About P2P</h3>
            <p className="text-sm text-slate-400">
              P2P mode allows direct connections between peers using NAT traversal.
              This reduces latency and increases privacy by avoiding central servers.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return null;
}

export default App;
