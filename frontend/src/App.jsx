import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Cpu, 
  Network, 
  Usb, 
  Activity, 
  Terminal, 
  AlertTriangle, 
  Trash2, 
  Play, 
  Settings as SettingsIcon, 
  CheckCircle, 
  XCircle, 
  RefreshCw,
  FolderOpen,
  Zap,
  Search
} from 'lucide-react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from 'chart.js';
import { Line } from 'react-chartjs-2';

// Register ChartJS plugins
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const API_BASE = `http://${window.location.hostname}:8000/api`;

function App() {
  // UI State
  const [activeTab, setActiveTab] = useState('processes'); // processes, network, filelogs, filescan
  const [showSettings, setShowSettings] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // EDR Data State
  const [status, setStatus] = useState({
    max_threat_score: 0.0,
    total_processes: 0,
    total_connections: 0,
    usb_connected: false,
    active_alerts_count: 0,
    auto_respond: true,
    simulation_mode: false,
    simulation_type: 'none'
  });
  const [processes, setProcesses] = useState([]);
  const [connections, setConnections] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [fileLogs, setFileLogs] = useState([]);
  const [settings, setSettings] = useState({
    auto_respond: 'true',
    auto_respond_threshold: '85.0',
    watchdog_path: '.'
  });
  
  // Simulation selected type
  const [simType, setSimType] = useState('none');
  
  // Threat score history for chart
  const [threatHistory, setThreatHistory] = useState(Array(15).fill(0));
  const [chartLabels, setChartLabels] = useState(Array(15).fill(''));

  // Static File Scanner State
  const [scanPath, setScanPath] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState(null);

  // Terminal scroll helper
  const terminalEndRef = useRef(null);

  // Poll intervals
  useEffect(() => {
    fetchInitialData();
    const interval = setInterval(() => {
      fetchUpdates();
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  // Scroll terminal logs to bottom on update
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [fileLogs]);

  const fetchInitialData = async () => {
    try {
      setLoading(true);
      const [statusRes, settingsRes] = await Promise.all([
        axios.get(`${API_BASE}/status`),
        axios.get(`${API_BASE}/settings`)
      ]);
      setStatus(statusRes.data);
      setSettings(settingsRes.data);
      setSimType(statusRes.data.simulation_type);
      
      await fetchUpdates();
      setError(null);
    } catch (err) {
      console.error(err);
      setError('Unable to communicate with SentinelX backend. Please verify uvicorn is running.');
    } finally {
      setLoading(false);
    }
  };

  const fetchUpdates = async () => {
    try {
      const [statusRes, procRes, netRes, alertsRes, logsRes] = await Promise.all([
        axios.get(`${API_BASE}/status`),
        axios.get(`${API_BASE}/processes`),
        axios.get(`${API_BASE}/network`),
        axios.get(`${API_BASE}/alerts`),
        axios.get(`${API_BASE}/file-logs`)
      ]);
      
      setStatus(statusRes.data);
      setProcesses(procRes.data);
      setConnections(netRes.data);
      setAlerts(alertsRes.data);
      setFileLogs(logsRes.data);
      
      // Update threat score history
      setThreatHistory(prev => {
        const next = [...prev.slice(1), statusRes.data.max_threat_score];
        return next;
      });
      setChartLabels(prev => {
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const next = [...prev.slice(1), time];
        return next;
      });
    } catch (err) {
      console.error('Error polling data:', err);
    }
  };

  // Actions
  const handleKillProcess = async (pid) => {
    try {
      const confirmKill = window.confirm(`Terminate process PID ${pid}?`);
      if (!confirmKill) return;
      
      await axios.post(`${API_BASE}/kill/${pid}`);
      fetchUpdates();
    } catch (err) {
      alert(`Failed to terminate process: ${err.response?.data?.detail || err.message}`);
    }
  };

  const handleDismissAlert = async (id) => {
    try {
      await axios.post(`${API_BASE}/alerts/${id}/dismiss`);
      fetchUpdates();
    } catch (err) {
      console.error(err);
    }
  };

  const handleClearAlerts = async () => {
    try {
      await axios.post(`${API_BASE}/alerts/clear`);
      fetchUpdates();
    } catch (err) {
      console.error(err);
    }
  };

  const handleToggleSimulation = async (type) => {
    try {
      setSimType(type);
      await axios.post(`${API_BASE}/simulate`, { type });
      fetchUpdates();
    } catch (err) {
      console.error(err);
    }
  };

  const handleTogglePolicy = async () => {
    const updatedVal = settings.auto_respond === 'true' ? 'false' : 'true';
    try {
      const newSettings = { ...settings, auto_respond: updatedVal };
      setSettings(newSettings);
      await axios.post(`${API_BASE}/settings`, newSettings);
      fetchUpdates();
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API_BASE}/settings`, settings);
      setShowSettings(false);
      fetchUpdates();
    } catch (err) {
      alert('Failed to save settings.');
    }
  };

  const handleScanFile = async (e) => {
    e.preventDefault();
    setScanning(true);
    setScanError(null);
    setScanResult(null);
    try {
      const res = await axios.post(`${API_BASE}/scan-file`, { filepath: scanPath });
      setScanResult(res.data);
    } catch (err) {
      setScanError(err.response?.data?.detail || err.message || 'Error occurred during scan.');
    } finally {
      setScanning(false);
    }
  };

  // Chart configuration
  const chartData = {
    labels: chartLabels,
    datasets: [
      {
        label: 'Max System Threat Score',
        data: threatHistory,
        borderColor: status.max_threat_score > 85 ? '#DC2626' : status.max_threat_score > 40 ? '#D97706' : '#059669',
        backgroundColor: (context) => {
          const ctx = context.chart.ctx;
          const gradient = ctx.createLinearGradient(0, 0, 0, 150);
          if (status.max_threat_score > 85) {
            gradient.addColorStop(0, 'rgba(220, 38, 38, 0.15)');
            gradient.addColorStop(1, 'rgba(220, 38, 38, 0)');
          } else if (status.max_threat_score > 40) {
            gradient.addColorStop(0, 'rgba(217, 119, 6, 0.15)');
            gradient.addColorStop(1, 'rgba(217, 119, 6, 0)');
          } else {
            gradient.addColorStop(0, 'rgba(5, 150, 105, 0.15)');
            gradient.addColorStop(1, 'rgba(5, 150, 105, 0)');
          }
          return gradient;
        },
        borderWidth: 2,
        pointRadius: 2,
        tension: 0.4,
        fill: true,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
    },
    scales: {
      y: {
        min: 0,
        max: 100,
        grid: {
          color: 'rgba(0, 0, 0, 0.05)',
        },
        ticks: {
          color: '#64748B',
        },
      },
      x: {
        grid: {
          display: false,
        },
        ticks: {
          color: '#64748B',
          maxRotation: 0,
          autoSkip: true,
          maxTicksLimit: 6,
        },
      },
    },
  };

  const getThreatColor = (score) => {
    if (score >= 80) return 'text-cyber-danger border-cyber-danger/30 bg-cyber-danger/10';
    if (score >= 40) return 'text-cyber-warning border-cyber-warning/30 bg-cyber-warning/10';
    return 'text-cyber-glow border-cyber-glow/30 bg-cyber-glow/10';
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 text-xs font-bold bg-red-50 border border-red-500 text-red-600 rounded-full animate-pulse">CRITICAL</span>;
      case 'WARNING':
        return <span className="px-2 py-0.5 text-xs font-semibold bg-amber-50 border border-amber-500 text-amber-600 rounded-full">WARNING</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-medium bg-blue-50 border border-blue-500 text-blue-600 rounded-full">INFO</span>;
    }
  };

  return (
    <div className="min-h-screen flex flex-col font-sans relative overflow-x-hidden grid-bg">
      {/* Top Banner for Error */}
      {error && (
        <div className="bg-cyber-danger text-white py-2.5 px-4 text-center text-sm font-semibold flex items-center justify-center gap-2 animate-bounce z-50">
          <ShieldAlert size={18} />
          {error}
          <button 
            onClick={fetchInitialData} 
            className="ml-3 px-3 py-1 bg-white/20 hover:bg-white/30 rounded text-xs transition flex items-center gap-1"
            id="retry-connect-btn"
          >
            <RefreshCw size={12} /> Retry
          </button>
        </div>
      )}

      {/* Main Header */}
      <header className="glass-panel border-b border-cyber-border py-4 px-6 sticky top-0 z-40 flex flex-wrap gap-4 items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-gradient-to-tr from-cyber-glow/20 to-blue-500/10 border border-cyber-glow/30 rounded-xl shadow-glow-green">
            <Shield size={28} className="text-cyber-glow" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wider text-slate-800 flex items-center gap-2">
              SENTINEL<span className="text-cyber-glow font-extrabold">X</span>
              <span className="text-xs font-mono px-2 py-0.5 border border-cyber-glow/30 bg-cyber-glow/10 text-cyber-glow rounded-md tracking-normal">EDR v1.0</span>
            </h1>
            <p className="text-xs text-cyber-muted font-mono">Autonomous endpoint threat monitor & response</p>
          </div>
        </div>

        {/* Real-time System state */}
        <div className="flex items-center gap-5 flex-wrap">
          {/* Status Indicator */}
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border font-mono text-sm transition ${
            status.max_threat_score >= 80 
              ? 'bg-red-50 border-red-500/40 text-red-600 glow-active-red' 
              : 'bg-emerald-50 border-cyber-glow/30 text-cyber-glow'
          }`}>
            {status.max_threat_score >= 80 ? (
              <>
                <ShieldAlert size={16} className="animate-bounce" />
                <span>STATE: COMPROMISED</span>
              </>
            ) : (
              <>
                <ShieldCheck size={16} />
                <span>STATE: SECURE</span>
              </>
            )}
          </div>

          {/* Quick Simulation Select */}
          <div className="flex items-center gap-2 bg-cyber-card border border-cyber-border rounded-lg p-1">
            <span className="text-xs font-mono text-cyber-muted px-2 flex items-center gap-1">
              <Zap size={13} className="text-cyber-warning" /> Live Simulation:
            </span>
            <button
              onClick={() => handleToggleSimulation('none')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                simType === 'none' ? 'bg-slate-200 text-slate-800' : 'text-cyber-muted hover:text-slate-800'
              }`}
              id="sim-none-btn"
            >
              Off
            </button>
            <button
              onClick={() => handleToggleSimulation('miner')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                simType === 'miner' ? 'bg-amber-600/20 border border-amber-500/30 text-amber-800 shadow-glow-amber' : 'text-cyber-muted hover:text-slate-800'
              }`}
              id="sim-miner-btn"
            >
              Cryptominer
            </button>
            <button
              onClick={() => handleToggleSimulation('ransomware')}
              className={`px-3 py-1 text-xs font-medium rounded-md transition ${
                simType === 'ransomware' ? 'bg-red-600/20 border border-red-500/30 text-red-800 shadow-glow-red' : 'text-cyber-muted hover:text-slate-800'
              }`}
              id="sim-ransom-btn"
            >
              Ransomware
            </button>
          </div>

          {/* Policy Armed Toggle */}
          <div className="flex items-center gap-2 bg-cyber-card border border-cyber-border rounded-lg px-3 py-1.5">
            <span className="text-xs font-mono text-cyber-muted">Auto-Response:</span>
            <button
              onClick={handleTogglePolicy}
              className={`relative inline-flex h-5 w-10 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                status.auto_respond ? 'bg-cyber-glow' : 'bg-slate-300'
              }`}
              id="policy-toggle"
            >
              <span
                className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                  status.auto_respond ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>

          {/* Settings Trigger */}
          <button 
            onClick={() => setShowSettings(true)}
            className="p-2 bg-cyber-card border border-cyber-border hover:bg-slate-100 rounded-lg text-cyber-text transition"
            id="open-settings-btn"
          >
            <SettingsIcon size={18} />
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 lg:p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* LEFT COLUMN: Gauges, Policy, Alerts, Live Logs */}
        <section className="lg:col-span-1 flex flex-col gap-6">
          
          {/* AI Threat Score Card */}
          <div className="glass-panel rounded-2xl p-5 relative overflow-hidden flex items-center justify-between border-t-2 border-t-cyber-glow/40">
            {/* Background glowing circle */}
            <div className={`absolute -right-10 -bottom-10 w-32 h-32 rounded-full filter blur-3xl opacity-15 ${
              status.max_threat_score >= 80 ? 'bg-cyber-danger' : status.max_threat_score >= 40 ? 'bg-cyber-warning' : 'bg-cyber-glow'
            }`} />
            
            <div className="flex flex-col gap-1">
              <span className="text-xs font-mono text-cyber-muted tracking-wider uppercase">Max active Threat Score</span>
              <span className={`text-4xl font-extrabold tracking-tight ${
                status.max_threat_score >= 80 ? 'text-cyber-danger' : status.max_threat_score >= 40 ? 'text-cyber-warning' : 'text-cyber-glow'
              }`}>
                {status.max_threat_score.toFixed(1)}%
              </span>
              <span className="text-xs text-cyber-muted mt-2 font-mono flex items-center gap-1">
                <CheckCircle size={12} className="text-cyber-glow" /> 
                Policy Limit: {settings.auto_respond_threshold}%
              </span>
            </div>

            <div className="w-24 h-24 relative flex items-center justify-center">
              {/* Radial Score Gauge */}
              <svg className="w-full h-full transform -rotate-95" viewBox="0 0 36 36">
                <path
                  className="text-slate-200"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845
                    a 15.9155 15.9155 0 0 1 0 31.831
                    a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={`transition-all duration-1000 ${
                    status.max_threat_score >= 80 
                      ? 'text-cyber-danger' 
                      : status.max_threat_score >= 40 
                        ? 'text-cyber-warning' 
                        : 'text-cyber-glow'
                  }`}
                  strokeWidth="3.5"
                  strokeDasharray={`${status.max_threat_score}, 100`}
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845
                    a 15.9155 15.9155 0 0 1 0 31.831
                    a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center flex-col">
                <span className="text-xs font-mono text-cyber-muted uppercase">Risk</span>
                <span className="text-xs font-bold text-slate-800 uppercase">
                  {status.max_threat_score >= 80 ? 'Critical' : status.max_threat_score >= 40 ? 'Medium' : 'Low'}
                </span>
              </div>
            </div>
          </div>

          {/* Quick Metrics grid */}
          <div className="grid grid-cols-3 gap-4">
            <div className="glass-panel rounded-xl p-4 flex flex-col gap-1 items-center text-center">
              <Cpu size={18} className="text-cyber-info mb-1" />
              <span className="text-xl font-bold text-slate-800">{status.total_processes}</span>
              <span className="text-[10px] uppercase tracking-wider font-mono text-cyber-muted">Processes</span>
            </div>
            
            <div className="glass-panel rounded-xl p-4 flex flex-col gap-1 items-center text-center">
              <Network size={18} className="text-indigo-600 mb-1" />
              <span className="text-xl font-bold text-slate-800">{status.total_connections}</span>
              <span className="text-[10px] uppercase tracking-wider font-mono text-cyber-muted">Connections</span>
            </div>

            <div className={`glass-panel rounded-xl p-4 flex flex-col gap-1 items-center text-center border transition ${
              status.usb_connected ? 'border-amber-500 bg-amber-50' : 'border-transparent'
            }`}>
              <Usb size={18} className={`${status.usb_connected ? 'text-cyber-warning animate-bounce' : 'text-cyber-muted'} mb-1`} />
              <span className="text-sm font-bold text-slate-800 truncate max-w-full">
                {status.usb_connected ? 'Unknown' : 'Secure'}
              </span>
              <span className="text-[10px] uppercase tracking-wider font-mono text-cyber-muted">USB Drive</span>
            </div>
          </div>

          {/* Threat Chart Card */}
          <div className="glass-panel rounded-2xl p-5 flex flex-col gap-3">
            <h3 className="text-sm font-semibold text-slate-800 tracking-wider flex items-center gap-1.5">
              <Activity size={16} className="text-cyber-glow" /> System Threat Activity Log
            </h3>
            <div className="h-36 w-full relative">
              <Line data={chartData} options={chartOptions} />
            </div>
          </div>

          {/* Active Alerts List */}
          <div className="glass-panel rounded-2xl p-5 flex-1 flex flex-col gap-3 overflow-hidden min-h-[300px]">
            <div className="flex justify-between items-center pb-2 border-b border-slate-200">
              <h3 className="text-sm font-semibold text-slate-800 tracking-wider flex items-center gap-1.5">
                <AlertTriangle size={16} className="text-cyber-danger" /> Active Threats & Mitigation
              </h3>
              {alerts.length > 0 && (
                <button 
                  onClick={handleClearAlerts}
                  className="text-xs text-cyber-muted hover:text-cyber-danger flex items-center gap-1 transition"
                  id="clear-alerts-btn"
                >
                  <Trash2 size={12} /> Clear Logs
                </button>
              )}
            </div>

            <div className="flex-1 overflow-y-auto flex flex-col gap-3 pr-1">
              {alerts.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center text-center text-cyber-muted gap-2">
                  <ShieldCheck size={28} className="text-cyber-glow opacity-40" />
                  <span className="text-xs font-mono">No active threats detected.</span>
                </div>
              ) : (
                alerts.map((alert) => (
                  <div 
                    key={alert.id} 
                    className={`p-3 rounded-lg border flex flex-col gap-2 transition ${
                      alert.severity === 'CRITICAL' 
                        ? 'bg-red-50 border-red-200' 
                        : alert.severity === 'WARNING' 
                          ? 'bg-amber-50 border-amber-200' 
                          : 'bg-slate-50 border-cyber-border'
                    }`}
                  >
                    <div className="flex justify-between items-start gap-2">
                      <div className="flex items-center gap-1.5">
                        {getSeverityBadge(alert.severity)}
                        <span className="text-xs font-bold text-slate-800">{alert.type} Incident</span>
                      </div>
                      <span className="text-[10px] text-cyber-muted font-mono">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <p className="text-xs text-slate-700 font-mono leading-relaxed break-all">
                      {alert.message}
                    </p>

                    <div className="flex justify-between items-center pt-1 mt-1 border-t border-slate-200">
                      <div className="flex items-center gap-1">
                        <span className="text-[10px] text-cyber-muted uppercase tracking-wider font-mono">Source:</span>
                        <span className="text-[10px] font-bold text-slate-700 truncate max-w-[120px]">{alert.source}</span>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        {alert.status === 'ACTIVE' && alert.type === 'PROCESS' && (
                          <button
                            onClick={() => handleKillProcess(parseInt(alert.source) || alert.source)}
                            className="px-2 py-0.5 bg-red-100 hover:bg-red-200 border border-red-300 text-red-800 rounded text-[10px] font-mono transition"
                          >
                            Mitigate Process
                          </button>
                        )}
                        {alert.status === 'ACTIVE' ? (
                          <button
                            onClick={() => handleDismissAlert(alert.id)}
                            className="px-2 py-0.5 bg-cyber-card hover:bg-slate-100 text-cyber-muted hover:text-slate-800 rounded text-[10px] font-mono border border-cyber-border transition"
                          >
                            Resolve Alert
                          </button>
                        ) : (
                          <span className="text-[10px] text-cyber-glow font-mono flex items-center gap-0.5">
                            ✓ {alert.status}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

        </section>

        {/* RIGHT COLUMN: Interactive Tab Panels (Processes, Network Connections, Logs, static scanner) */}
        <section className="lg:col-span-2 flex flex-col gap-6">

          {/* Navigation Bar */}
          <div className="glass-panel rounded-2xl p-1.5 flex justify-between items-center overflow-x-auto">
            <nav className="flex gap-2 min-w-max">
              <button
                onClick={() => setActiveTab('processes')}
                className={`px-4 py-2 text-xs font-semibold uppercase tracking-wider font-mono rounded-xl transition flex items-center gap-1.5 ${
                  activeTab === 'processes' ? 'bg-slate-200/80 text-cyber-glow border border-slate-300/40' : 'text-cyber-muted hover:text-slate-800'
                }`}
                id="tab-processes"
              >
                <Cpu size={14} /> Process Monitor
              </button>
              <button
                onClick={() => setActiveTab('network')}
                className={`px-4 py-2 text-xs font-semibold uppercase tracking-wider font-mono rounded-xl transition flex items-center gap-1.5 ${
                  activeTab === 'network' ? 'bg-slate-200/80 text-cyber-glow border border-slate-300/40' : 'text-cyber-muted hover:text-slate-800'
                }`}
                id="tab-network"
              >
                <Network size={14} /> Network Sockets
              </button>
              <button
                onClick={() => setActiveTab('filelogs')}
                className={`px-4 py-2 text-xs font-semibold uppercase tracking-wider font-mono rounded-xl transition flex items-center gap-1.5 ${
                  activeTab === 'filelogs' ? 'bg-slate-200/80 text-cyber-glow border border-slate-300/40' : 'text-cyber-muted hover:text-slate-800'
                }`}
                id="tab-filelogs"
              >
                <Terminal size={14} /> Directory Audit
              </button>
              <button
                onClick={() => setActiveTab('filescan')}
                className={`px-4 py-2 text-xs font-semibold uppercase tracking-wider font-mono rounded-xl transition flex items-center gap-1.5 ${
                  activeTab === 'filescan' ? 'bg-slate-200/80 text-cyber-glow border border-slate-300/40' : 'text-cyber-muted hover:text-slate-800'
                }`}
                id="tab-filescan"
              >
                <Search size={14} /> File Scanner
              </button>
            </nav>

            <span className="text-xs text-cyber-muted pr-3 font-mono flex items-center gap-1.5 min-w-max">
              <span className="w-2 h-2 rounded-full bg-cyber-glow animate-ping" /> Real-time active
            </span>
          </div>

          {/* TAB 1: PROCESS MONITOR */}
          {activeTab === 'processes' && (
            <div className="glass-panel rounded-2xl p-5 flex flex-col gap-4 flex-1 overflow-hidden min-h-[450px]">
              <div className="flex justify-between items-center">
                <div>
                  <h2 className="text-base font-bold text-slate-800">AI Evaluated Endpoint Processes</h2>
                  <p className="text-xs text-cyber-muted font-mono">Dynamic threat indexing matching live performance to ML classifier models.</p>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto border border-slate-200 rounded-xl bg-white">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-50 border-b border-slate-200 sticky top-0 z-10 text-cyber-muted uppercase tracking-wider">
                    <tr>
                      <th className="py-3 px-4">PID</th>
                      <th className="py-3 px-4">Process Name</th>
                      <th className="py-3 px-4">CPU%</th>
                      <th className="py-3 px-4">Memory</th>
                      <th className="py-3 px-4">Net Conn</th>
                      <th className="py-3 px-4">Threat Index</th>
                      <th className="py-3 px-4 text-center">Response</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {processes.length === 0 ? (
                      <tr>
                        <td colSpan="7" className="py-8 text-center text-cyber-muted">Scanning processes...</td>
                      </tr>
                    ) : (
                      processes.map((proc) => {
                        return (
                          <tr 
                            key={proc.pid} 
                            className={`hover:bg-slate-50 transition group ${
                              proc.threat_score >= 80 
                                ? 'bg-red-50 text-red-900 hover:bg-red-100' 
                                : proc.threat_score >= 40 
                                  ? 'bg-amber-50 text-amber-900' 
                                  : 'text-slate-800'
                            }`}
                          >
                            <td className="py-3.5 px-4 font-bold text-cyber-muted">{proc.pid}</td>
                            <td className="py-3.5 px-4">
                              <div className="flex flex-col">
                                <span className="font-semibold text-slate-800 group-hover:text-cyber-glow transition">{proc.name}</span>
                                <span className="text-[10px] text-cyber-muted truncate max-w-[200px]" title={proc.exe}>{proc.exe}</span>
                              </div>
                            </td>
                            <td className="py-3.5 px-4">{proc.cpu}%</td>
                            <td className="py-3.5 px-4">{proc.memory.toFixed(1)} MB</td>
                            <td className="py-3.5 px-4">{proc.connections}</td>
                            <td className="py-3.5 px-4">
                              <div className="flex items-center gap-2">
                                <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${getThreatColor(proc.threat_score)}`}>
                                  {proc.threat_score}%
                                </span>
                                <span className="text-[10px] text-cyber-muted hidden md:inline truncate max-w-[150px]" title={proc.explanation}>
                                  {proc.explanation}
                                </span>
                              </div>
                            </td>
                            <td className="py-3.5 px-4 text-center">
                              <button
                                onClick={() => handleKillProcess(proc.pid)}
                                className={`px-2.5 py-1 rounded text-[10px] font-semibold border transition ${
                                  proc.threat_score >= 80 
                                    ? 'bg-cyber-danger hover:bg-red-600 border-red-500/20 text-white' 
                                    : 'bg-cyber-card border-cyber-border text-cyber-muted hover:text-cyber-danger hover:border-red-500/40'
                                }`}
                              >
                                Kill Process
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 2: NETWORK CONNECTIONS */}
          {activeTab === 'network' && (
            <div className="glass-panel rounded-2xl p-5 flex flex-col gap-4 flex-1 overflow-hidden min-h-[450px]">
              <div>
                <h2 className="text-base font-bold text-slate-800">Active Endpoint Sockets</h2>
                <p className="text-xs text-cyber-muted font-mono">Live mapping of local sockets to remote addresses and process owners.</p>
              </div>

              <div className="flex-1 overflow-y-auto border border-slate-200 rounded-xl bg-white">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-50 border-b border-slate-200 sticky top-0 z-10 text-cyber-muted uppercase tracking-wider">
                    <tr>
                      <th className="py-3 px-4">PID</th>
                      <th className="py-3 px-4">Process Name</th>
                      <th className="py-3 px-4">Local Socket</th>
                      <th className="py-3 px-4">Remote Socket</th>
                      <th className="py-3 px-4">Protocol</th>
                      <th className="py-3 px-4">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-slate-800">
                    {connections.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="py-8 text-center text-cyber-muted">No active network connections detected.</td>
                      </tr>
                    ) : (
                      connections.map((conn, idx) => (
                        <tr key={idx} className="hover:bg-slate-50 transition">
                          <td className="py-3.5 px-4 font-bold text-cyber-muted">{conn.pid}</td>
                          <td className="py-3.5 px-4 font-semibold text-slate-800">{conn.name}</td>
                          <td className="py-3.5 px-4">{conn.laddr}</td>
                          <td className="py-3.5 px-4 font-bold">{conn.raddr}</td>
                          <td className="py-3.5 px-4 text-cyber-muted">{conn.type}</td>
                          <td className="py-3.5 px-4">
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                              conn.status === 'ESTABLISHED' 
                                ? 'bg-emerald-50 border border-emerald-300 text-emerald-600' 
                                : 'bg-slate-100 border border-cyber-border text-cyber-muted'
                            }`}>
                              {conn.status}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: DIRECTORY AUDIT (WATCHDOG LOGS) */}
          {activeTab === 'filelogs' && (
            <div className="glass-panel rounded-2xl p-5 flex flex-col gap-4 flex-1 overflow-hidden min-h-[450px]">
              <div>
                <h2 className="text-base font-bold text-slate-800">Live File Auditing</h2>
                <p className="text-xs text-cyber-muted font-mono">Real-time surveillance of user folders (Documents, Downloads, Desktop) using Watchdog events.</p>
              </div>

              {/* Watch folder path display */}
              <div className="p-3 bg-cyber-card border border-cyber-border rounded-xl flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FolderOpen size={16} className="text-cyber-glow" />
                  <span className="text-xs text-cyber-muted font-mono">Monitoring target path:</span>
                  <span className="text-xs font-mono text-slate-800 bg-slate-100 px-2.5 py-1 rounded border border-slate-200">{settings.watchdog_path}</span>
                </div>
                
                {/* Simulation trigger */}
                <button
                  onClick={async () => {
                    alert("Please create a file named 'invoice.pdf.exe' in the monitored folder to test live watchdog triggers!");
                  }}
                  className="px-2.5 py-1 bg-cyber-card border border-cyber-border text-cyber-glow hover:bg-cyber-glow hover:text-white rounded text-[10px] font-mono transition"
                >
                  Trigger File Alert Sim
                </button>
              </div>

              {/* Terminal container */}
              <div className="flex-1 bg-slate-950 rounded-xl p-4 font-mono text-xs overflow-y-auto border border-slate-800 flex flex-col gap-1.5 shadow-inner select-text">
                {fileLogs.length === 0 ? (
                  <span className="text-slate-500 italic">Listening for local file changes (creates, modifies, deletes)...</span>
                ) : (
                  fileLogs.map((log, idx) => {
                    const isDanger = log.toLowerCase().includes('.exe') || log.toLowerCase().includes('.locked');
                    return (
                      <div 
                        key={idx} 
                        className={`leading-relaxed border-l-2 pl-2 ${
                          isDanger ? 'text-red-400 border-red-500 animate-pulse font-bold' : 'text-emerald-400 border-emerald-500'
                        }`}
                      >
                        {log}
                      </div>
                    );
                  })
                )}
                <div ref={terminalEndRef} />
              </div>
            </div>
          )}

          {/* TAB 4: STATIC FILE SCANNER */}
          {activeTab === 'filescan' && (
            <div className="glass-panel rounded-2xl p-5 flex flex-col gap-4 flex-1 min-h-[450px]">
              <div>
                <h2 className="text-base font-bold text-slate-800">Static Signature File Scanner</h2>
                <p className="text-xs text-cyber-muted font-mono">Perform static security analysis, compute file checksums, and check against signature databases.</p>
              </div>

              <form onSubmit={handleScanFile} className="flex gap-2">
                <input 
                  type="text"
                  placeholder="Enter absolute file path (e.g. D:\OSF Hackathon\watch_folder\invoice.pdf.exe)"
                  value={scanPath}
                  onChange={(e) => setScanPath(e.target.value)}
                  className="flex-1 bg-slate-50 border border-cyber-border rounded-xl px-3 py-2 text-sm text-slate-800 focus:outline-none focus:border-cyber-glow font-mono"
                  required
                />
                <button
                  type="submit"
                  disabled={scanning}
                  className="px-5 py-2 bg-cyber-glow hover:bg-emerald-600 text-xs font-semibold rounded-xl text-white font-mono transition disabled:opacity-50 flex items-center gap-1.5"
                >
                  {scanning ? <RefreshCw size={13} className="animate-spin" /> : <Play size={13} />} Scan File
                </button>
              </form>

              {scanResult && (
                <div className={`p-4 rounded-xl border flex flex-col gap-3 font-mono text-xs ${
                  scanResult.status === 'INFECTED' 
                    ? 'bg-red-50 border-red-200 text-red-900' 
                    : 'bg-emerald-50 border-emerald-200 text-emerald-950'
                }`}>
                  <div className="flex items-center gap-2 border-b pb-2">
                    {scanResult.status === 'INFECTED' ? (
                      <XCircle size={18} className="text-cyber-danger" />
                    ) : (
                      <CheckCircle size={18} className="text-cyber-glow" />
                    )}
                    <span className="font-bold text-sm">SCAN RESULT: {scanResult.status}</span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                    <div>
                      <span className="text-cyber-muted uppercase block text-[10px]">Filename</span>
                      <span className="font-semibold text-slate-800 break-all">{scanResult.filename}</span>
                    </div>
                    <div>
                      <span className="text-cyber-muted uppercase block text-[10px]">File size</span>
                      <span className="font-semibold text-slate-800">{scanResult.size_kb} KB</span>
                    </div>
                    <div className="md:col-span-2">
                      <span className="text-cyber-muted uppercase block text-[10px]">SHA-256 Hash</span>
                      <span className="font-semibold text-slate-800 break-all select-all">{scanResult.sha256}</span>
                    </div>
                    {scanResult.status === 'INFECTED' && (
                      <div>
                        <span className="text-cyber-muted uppercase block text-[10px]">Detected Signature</span>
                        <span className="font-bold text-cyber-danger">{scanResult.threat_type}</span>
                      </div>
                    )}
                    <div className="md:col-span-2">
                      <span className="text-cyber-muted uppercase block text-[10px]">Analysis Details</span>
                      <span className="text-slate-700 font-semibold">{scanResult.details}</span>
                    </div>
                  </div>
                </div>
              )}

              {scanError && (
                <div className="p-3 bg-red-50 border border-red-200 text-red-700 text-xs font-mono rounded-xl flex items-center gap-2">
                  <XCircle size={15} />
                  {scanError}
                </div>
              )}
            </div>
          )}

        </section>
      </main>

      {/* FOOTER */}
      <footer className="glass-panel border-t border-cyber-border py-4 px-6 mt-8 flex flex-col md:flex-row justify-between items-center gap-2 text-xs text-cyber-muted font-mono">
        <span>SentinelX © 2026 Hackathon EDR Prototype. All rights reserved.</span>
        <div className="flex items-center gap-4">
          <span>Target Platform: Windows Endpoint Agent</span>
          <span>•</span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-cyber-glow animate-pulse" /> AI Engine Online
          </span>
        </div>
      </footer>

      {/* SETTINGS DIALOG MODAL */}
      {showSettings && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="glass-panel-heavy rounded-2xl max-w-md w-full p-6 border border-cyber-border flex flex-col gap-4 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex justify-between items-center border-b border-slate-200 pb-3">
              <h2 className="text-base font-bold text-slate-800 flex items-center gap-2">
                <SettingsIcon size={18} className="text-cyber-glow" /> SentinelX Settings
              </h2>
              <button 
                onClick={() => setShowSettings(false)}
                className="text-cyber-muted hover:text-slate-800 transition font-mono text-sm"
              >
                Close
              </button>
            </div>

            <form onSubmit={handleSaveSettings} className="flex flex-col gap-4">
              {/* Auto Response Threshold */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-slate-700 font-mono">
                  Auto-Mitigation Threat Threshold (%)
                </label>
                <input 
                  type="number"
                  min="0"
                  max="100"
                  value={settings.auto_respond_threshold}
                  onChange={(e) => setSettings({ ...settings, auto_respond_threshold: e.target.value })}
                  className="w-full bg-slate-50 border border-cyber-border rounded-lg px-3 py-2 text-sm text-slate-800 focus:outline-none focus:border-cyber-glow font-mono"
                  required
                />
                <span className="text-[10px] text-cyber-muted leading-relaxed font-mono">
                  Processes scoring above this threshold are automatically terminated via System API if auto-response policy is armed.
                </span>
              </div>

              {/* Watchdog path */}
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-slate-700 font-mono">
                  File Monitoring Base Directory
                </label>
                <input 
                  type="text"
                  value={settings.watchdog_path}
                  onChange={(e) => setSettings({ ...settings, watchdog_path: e.target.value })}
                  className="w-full bg-slate-50 border border-cyber-border rounded-lg px-3 py-2 text-sm text-slate-800 focus:outline-none focus:border-cyber-glow font-mono"
                  required
                />
                <span className="text-[10px] text-cyber-muted leading-relaxed font-mono">
                  Path for Watchdog filesystem monitoring. Set to '.' to monitor project workspace.
                </span>
              </div>

              <div className="flex justify-end gap-2 pt-4 border-t border-slate-200">
                <button
                  type="button"
                  onClick={() => setShowSettings(false)}
                  className="px-4 py-2 bg-cyber-card border border-cyber-border hover:bg-slate-100 text-xs font-semibold rounded-lg text-slate-700 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyber-glow hover:bg-emerald-600 text-xs font-semibold rounded-lg text-white transition"
                >
                  Save Policy Config
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
