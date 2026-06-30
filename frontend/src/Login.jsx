import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "./services/api";
import { useAuth } from "./auth/AuthContext";
import { Shield, Lock, User, Terminal, ChevronRight, AlertCircle, Cpu, Eye } from "lucide-react";

export default function Login({ onLogin }) {
  const navigate = useNavigate();
  const authContext = useAuth();
  
  // Support both context login and prop callback if provided
  const loginUser = (data) => {
    if (authContext && authContext.login) {
      authContext.login(data);
    }
    if (onLogin) {
      onLogin(data);
    }
  };

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  
  const [selectedRole, setSelectedRole] = useState(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [loginSteps, setLoginSteps] = useState([]);

  const rolesConfig = {
    viewer: {
      name: "Viewer",
      icon: Eye,
      color: "emerald",
      badgeClass: "bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-semibold px-2.5 py-1 rounded-md",
      accentColor: "#059669",
      hoverClass: "border-emerald-300 bg-emerald-50/50 shadow-sm",
      selectedClass: "border-emerald-500 bg-emerald-50 shadow-sm ring-1 ring-emerald-500",
      description: "Read-only access to endpoints, process listings, socket events, and safety logs. Auto-mitigation and settings locked.",
      username: "viewer",
      password: "viewer123"
    },
    analyst: {
      name: "Analyst",
      icon: Cpu,
      color: "amber",
      badgeClass: "bg-amber-50 border border-amber-200 text-amber-700 text-xs font-semibold px-2.5 py-1 rounded-md",
      accentColor: "#D97706",
      hoverClass: "border-amber-300 bg-amber-50/50 shadow-sm",
      selectedClass: "border-amber-500 bg-amber-50 shadow-sm ring-1 ring-amber-500",
      description: "Perform system audits, manage active threat logs, terminate malicious processes, and execute static file scanner signatures.",
      username: "analyst",
      password: "analyst123"
    },
    admin: {
      name: "Administrator",
      icon: Shield,
      color: "rose",
      badgeClass: "bg-rose-50 border border-rose-200 text-rose-700 text-xs font-semibold px-2.5 py-1 rounded-md",
      accentColor: "#E11D48",
      hoverClass: "border-rose-300 bg-rose-50/50 shadow-sm",
      selectedClass: "border-rose-500 bg-rose-50 shadow-sm ring-1 ring-rose-500",
      description: "Unrestricted security credentials. Modify watchdog folders, arm auto-mitigation thresholds, and trigger endpoint simulations.",
      username: "admin",
      password: "admin123"
    }
  };

  const handleRoleSelect = (roleKey) => {
    setSelectedRole(roleKey);
    setUsername(rolesConfig[roleKey].username);
    setPassword(rolesConfig[roleKey].password);
    setError("");
  };

  const runLoginSequence = async () => {
    setIsLoggingIn(true);
    setLoginSteps([]);
    
    const steps = [
      { text: "Initializing cryptographic handshake...", delay: 200 },
      { text: `Locating node access directory [role: ${selectedRole?.toUpperCase() || "CUSTOM"}]...`, delay: 350 },
      { text: "Validating JWT authorization payload...", delay: 300 },
      { text: "Decrypting environment credentials...", delay: 250 },
      { text: "Establishing secure session context...", delay: 200 }
    ];

    for (let i = 0; i < steps.length; i++) {
      await new Promise(resolve => setTimeout(resolve, steps[i].delay));
      setLoginSteps(prev => [...prev, { text: steps[i].text, type: 'info' }]);
    }

    try {
      const res = await api.post("/auth/login", {
        username,
        password,
      });
      
      setLoginSteps(prev => [...prev, { text: "✓ Access Granted. Redirecting...", type: 'success' }]);
      await new Promise(resolve => setTimeout(resolve, 300));
      
      localStorage.setItem("token", res.data.access_token);
      localStorage.setItem("role", res.data.role);
      localStorage.setItem("username", res.data.username);

      loginUser(res.data);
      navigate("/dashboard");
    } catch (err) {
      setLoginSteps(prev => [...prev, { text: "✕ Access Denied: Invalid Security Signature.", type: 'error' }]);
      await new Promise(resolve => setTimeout(resolve, 500));
      setError(err.response?.data?.detail || "Authentication handshake failed.");
      setIsLoggingIn(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!username || !password) {
      setError("Please input security credentials.");
      return;
    }
    runLoginSequence();
  };

  return (
    <div 
      className="min-h-screen bg-[#F2F8F4] bg-cover bg-center text-slate-800 flex items-center justify-center relative overflow-hidden font-sans"
      style={{
        backgroundImage: "url('/cyber_login_bg.png')"
      }}
    >
      
      {/* Background Matrix Grid Overlay */}
      <div className="absolute inset-0 opacity-5 bg-[linear-gradient(to_right,#059669_1px,transparent_1px),linear-gradient(to_bottom,#059669_1px,transparent_1px)] bg-[size:4rem_4rem]"></div>
      
      {/* Ambient Neon Blobs */}
      <div className="absolute top-1/4 left-1/4 -translate-x-1/2 -translate-y-1/2 w-96 h-96 rounded-full bg-emerald-500/5 blur-[120px] pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 translate-x-1/2 translate-y-1/2 w-[500px] h-[500px] rounded-full bg-teal-500/5 blur-[140px] pointer-events-none"></div>
      {selectedRole && (
        <div 
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full blur-[160px] pointer-events-none transition-all duration-700"
          style={{
            backgroundColor: `${rolesConfig[selectedRole].accentColor}10`
          }}
        />
      )}

      {/* Login Box */}
      <div className="w-full max-w-4xl p-4 md:p-6 z-10">
        <div className="bg-white border-2 border-[#059669] rounded-3xl overflow-hidden shadow-[6px_6px_0px_0px_#0F172A] flex flex-col md:flex-row transition-all duration-300">
          
          {/* Left panel: Info & Logo */}
          <div className="md:w-5/12 p-8 bg-slate-50 border-b md:border-b-0 md:border-r border-slate-200 flex flex-col justify-between relative overflow-hidden">
            {/* Glowing lines */}
            <div className="absolute top-0 right-0 w-px h-full bg-gradient-to-b from-transparent via-slate-200 to-transparent"></div>
            
            <div className="flex flex-col gap-6">
              {/* Logo Header */}
              <div className="flex items-center gap-3">
                <div className="p-3 bg-white border border-slate-200 rounded-2xl shadow-sm relative group">
                  <Shield size={28} className="text-[#059669] relative z-10 animate-pulse" />
                </div>
                <div>
                  <h1 className="text-lg font-bold tracking-wider text-slate-900 flex items-center">
                    SENTINEL<span className="text-[#059669] font-extrabold">X</span>
                  </h1>
                  <p className="text-[10px] text-slate-500 font-mono">EDR CONTROL PORTAL</p>
                </div>
              </div>

              {/* Description */}
              <div className="space-y-4 my-4">
                <h2 className="text-xl font-bold text-slate-900">Endpoint Detection & Response</h2>
                <p className="text-xs text-slate-600 leading-relaxed font-mono">
                  Welcome to the SentinelX threat gateway. Select a role and input security credentials to authenticate key.
                </p>
              </div>
            </div>

            {/* System Status Panel */}
            <div className="mt-8 pt-6 border-t border-slate-200 font-mono text-[10px] text-slate-500 space-y-2">
              <div className="flex justify-between">
                <span>SYSTEM VERSION:</span>
                <span className="text-slate-700">1.0.0 (STABLE)</span>
              </div>
              <div className="flex justify-between">
                <span>NODE:</span>
                <span className="text-slate-700">LOCAL_GATEWAY_MAIN</span>
              </div>
              <div className="flex justify-between">
                <span>NETWORK STATUS:</span>
                <span className="text-emerald-600 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping"></span> SECURED
                </span>
              </div>
            </div>
          </div>

          {/* Right panel: Login controls */}
          <div className="md:w-7/12 p-8 flex flex-col justify-center relative bg-white">
            
            {isLoggingIn ? (
              /* DECRYPTION TERMINAL WORKFLOW */
              <div className="min-h-[350px] flex flex-col justify-between font-mono">
                <div>
                  <div className="flex items-center gap-2 border-b border-slate-200 pb-3 mb-6">
                    <Terminal size={16} className="text-emerald-600" />
                    <span className="text-xs font-bold text-slate-700 tracking-wider">ESTABLISHING SESSION SOCKET</span>
                  </div>
                  
                  <div className="space-y-3 text-xs">
                    {loginSteps.map((step, idx) => (
                      <div 
                        key={idx} 
                        className={`flex gap-2 transition-all duration-300 ${
                          step.type === 'error' ? 'text-rose-600' : 
                          step.type === 'success' ? 'text-emerald-600 font-bold' : 
                          'text-slate-800'
                        }`}
                      >
                        <span className="text-slate-400">[{idx + 1}]</span>
                        <span>{step.text}</span>
                      </div>
                    ))}
                    <div className="w-2.5 h-4 bg-slate-400 animate-pulse inline-block mt-1"></div>
                  </div>
                </div>
                
                <div className="text-[10px] text-slate-500 border-t border-slate-200 pt-4">
                  WARNING: Unauthorized access attempts are monitored and logged.
                </div>
              </div>
            ) : (
              /* PRIMARY FORM */
              <div className="space-y-6">
                <div>
                  <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 mb-4">
                    1. Select Access Authorization Role
                  </h3>
                  
                  {/* Role Cards Grid */}
                  <div className="grid grid-cols-3 gap-3">
                    {Object.keys(rolesConfig).map((roleKey) => {
                      const r = rolesConfig[roleKey];
                      const Icon = r.icon;
                      const isSelected = selectedRole === roleKey;
                      
                      return (
                        <button
                          key={roleKey}
                          type="button"
                          onClick={() => handleRoleSelect(roleKey)}
                          className={`flex flex-col items-center justify-center p-3 rounded-2xl border text-center transition-all duration-300 relative group cursor-pointer ${
                            isSelected ? r.selectedClass : "border-slate-200 bg-white hover:bg-slate-50"
                          }`}
                        >
                          <div className={`p-2 rounded-xl bg-slate-50 border border-slate-200 transition group-hover:scale-105 duration-300`}>
                            <Icon 
                              size={18} 
                              className="transition duration-300"
                              style={{ color: isSelected ? r.accentColor : '#64748b' }}
                            />
                          </div>
                          <span className="text-xs font-semibold text-slate-700 mt-2 block tracking-wide">
                            {r.name}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Selected Role Privilege description banner */}
                {selectedRole && (
                  <div className="p-3 bg-slate-50 border border-slate-200 rounded-2xl flex gap-3 text-xs leading-relaxed animate-in fade-in slide-in-from-top-1 duration-200">
                    <div className="flex flex-col gap-1.5">
                      <div className="flex items-center gap-2">
                        <span className={rolesConfig[selectedRole].badgeClass}>
                          ACCESS TYPE: {selectedRole.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-600 font-mono">
                        {rolesConfig[selectedRole].description}
                      </p>
                    </div>
                  </div>
                )}

                {/* Login Credentials Form */}
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div className="border-t border-slate-200 pt-4">
                    <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 mb-3">
                      2. Input Terminal Signatures
                    </h3>
                  </div>

                  {error && (
                    <div className="bg-rose-50 border border-rose-200 text-rose-700 text-xs rounded-xl p-3 flex items-start gap-2 animate-shake">
                      <AlertCircle size={16} className="shrink-0 mt-0.5" />
                      <span>{error}</span>
                    </div>
                  )}

                  <div className="space-y-3">
                    <div className="relative group">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400 group-focus-within:text-emerald-600 transition-colors">
                        <User size={16} />
                      </div>
                      <input
                        className="w-full bg-white border border-slate-200 hover:border-slate-300 focus:border-emerald-600 focus:ring-1 focus:ring-emerald-500/20 rounded-xl py-3 pl-10 pr-4 text-xs font-mono text-slate-800 focus:outline-none transition"
                        placeholder="Security Username"
                        value={username}
                        onChange={(e) => {
                          setUsername(e.target.value);
                          setSelectedRole(null);
                        }}
                        id="login-username-input-legacy"
                      />
                    </div>

                    <div className="relative group">
                      <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400 group-focus-within:text-emerald-600 transition-colors">
                        <Lock size={16} />
                      </div>
                      <input
                        type="password"
                        className="w-full bg-white border border-slate-200 hover:border-slate-300 focus:border-emerald-600 focus:ring-1 focus:ring-emerald-500/20 rounded-xl py-3 pl-10 pr-4 text-xs font-mono text-slate-800 focus:outline-none transition"
                        placeholder="Cryptographic Key"
                        value={password}
                        onChange={(e) => {
                          setPassword(e.target.value);
                          setSelectedRole(null);
                        }}
                        id="login-password-input-legacy"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    className="w-full mt-4 bg-[#059669] hover:bg-[#047857] text-white font-bold rounded-xl py-3 text-xs tracking-wider uppercase flex items-center justify-center gap-1.5 transition-all shadow-sm duration-300 cursor-pointer"
                    id="submit-login-btn-legacy"
                  >
                    <span>Authenticate Key</span>
                    <ChevronRight size={14} className="group-hover:translate-x-0.5 transition" />
                  </button>
                </form>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}