import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTranslation } from 'react-i18next';
import { scansAPI } from '../services/api';
import { Shield, Activity, AlertCircle, CheckCircle, Clock } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import LogoutModal from '../components/LogoutModal';
import LanguageSwitcher from '../components/LanguageSwitcher';
import './Dashboard.css';

function Dashboard() {
  const { t } = useTranslation();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    loadStatistics();
  }, []);

  const loadStatistics = async () => {
    try {
      const response = await scansAPI.getStatistics();
      setStats(response.data);
    } catch (error) {
      console.error('Failed to load statistics:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    setShowLogoutModal(false);
    logout();
    navigate('/login');
  };

  if (loading) {
    return (
      <div className="dashboard">
        <div className="loading">Loading...</div>
      </div>
    );
  }

  const COLORS = {
    critical: 'url(#criticalGradient)',
    high: 'url(#highGradient)',
    medium: 'url(#mediumGradient)',
    low: 'url(#lowGradient)',
  };

  const chartData = stats ? [
    { name: 'Critical', value: stats.vulnerabilities_by_severity.critical, color: COLORS.critical },
    { name: 'High', value: stats.vulnerabilities_by_severity.high, color: COLORS.high },
    { name: 'Medium', value: stats.vulnerabilities_by_severity.medium, color: COLORS.medium },
    { name: 'Low', value: stats.vulnerabilities_by_severity.low, color: COLORS.low },
  ].filter(item => item.value > 0) : [];

  return (
    <div className="dashboard">
      <nav className="navbar">
        <div className="navbar-brand">
          <Shield size={24} />
          <span>Vulnerability Scanner</span>
        </div>
        <div className="navbar-menu">
          <button onClick={() => navigate('/dashboard')} className="nav-link active">
            {t('nav.dashboard')}
          </button>
          <button onClick={() => navigate('/scans')} className="nav-link">
            {t('nav.scans')}
          </button>
          <button onClick={() => navigate('/new-scan')} className="nav-link">
            {t('nav.newScan')}
          </button>
          <LanguageSwitcher />
          <button onClick={() => setShowLogoutModal(true)} className="btn-logout">
            {t('nav.logout')}
          </button>
        </div>
      </nav>

      <LogoutModal 
        isOpen={showLogoutModal}
        onConfirm={handleLogout}
        onCancel={() => setShowLogoutModal(false)}
      />

      <div className="dashboard-content">
        <div className="dashboard-header">
          <h1>{t('dashboard.title')}</h1>
          <p>{t('dashboard.welcome', { name: user?.full_name })}</p>
        </div>

        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon" style={{ background: '#dbeafe' }}>
              <Activity size={24} style={{ color: '#2563eb' }} />
            </div>
            <div className="stat-info">
              <p className="stat-label">{t('dashboard.totalScans')}</p>
              <p className="stat-value">{stats?.total_scans || 0}</p>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon" style={{ background: '#dcfce7' }}>
              <CheckCircle size={24} style={{ color: '#16a34a' }} />
            </div>
            <div className="stat-info">
              <p className="stat-label">{t('dashboard.completed')}</p>
              <p className="stat-value">{stats?.completed_scans || 0}</p>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon" style={{ background: '#fef3c7' }}>
              <AlertCircle size={24} style={{ color: '#d97706' }} />
            </div>
            <div className="stat-info">
              <p className="stat-label">{t('dashboard.vulnerabilities')}</p>
              <p className="stat-value">{stats?.total_vulnerabilities || 0}</p>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon" style={{ background: '#e0e7ff' }}>
              <Clock size={24} style={{ color: '#6366f1' }} />
            </div>
            <div className="stat-info">
              <p className="stat-label">{t('dashboard.avgDuration')}</p>
              <p className="stat-value">{stats?.average_scan_duration?.toFixed(1) || 0}s</p>
            </div>
          </div>
        </div>

        <div className="dashboard-row">
          <div className="chart-card">
            <h2>{t('dashboard.vulnerabilitiesBySeverity')}</h2>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <defs>
                    <linearGradient id="criticalGradient" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#dc2626" />
                      <stop offset="100%" stopColor="#991b1b" />
                    </linearGradient>
                    <linearGradient id="highGradient" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#f59e0b" />
                      <stop offset="100%" stopColor="#d97706" />
                    </linearGradient>
                    <linearGradient id="mediumGradient" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#fbbf24" />
                      <stop offset="100%" stopColor="#f59e0b" />
                    </linearGradient>
                    <linearGradient id="lowGradient" x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor="#84cc16" />
                      <stop offset="100%" stopColor="#65a30d" />
                    </linearGradient>
                  </defs>
                  <Pie
                    data={chartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={100}
                    innerRadius={60}
                    paddingAngle={5}
                    label={(entry) => `${entry.name}: ${entry.value}`}
                    labelLine={false}
                  >
                    {chartData.map((entry, index) => (
                      <Cell 
                        key={`cell-${index}`} 
                        fill={COLORS[entry.name.toLowerCase()]}
                        stroke="white"
                        strokeWidth={2}
                      />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{
                      background: 'rgba(255, 255, 255, 0.95)',
                      border: 'none',
                      borderRadius: '12px',
                      boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                      padding: '12px'
                    }}
                  />
                  <Legend 
                    verticalAlign="bottom"
                    height={36}
                    iconType="circle"
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <p className="no-data">{t('dashboard.noData')}</p>
            )}
          </div>

          <div className="recent-scans-card">
            <h2>{t('dashboard.recentScans')}</h2>
            {stats?.recent_scans?.length > 0 ? (
              <div className="scans-list">
                {stats.recent_scans.map((scan) => (
                  <div key={scan.id} className="scan-item" onClick={() => navigate(`/scans/${scan.id}`)}>
                    <div>
                      <p className="scan-url">{scan.target_url}</p>
                      <p className="scan-date">{new Date(scan.created_at).toLocaleDateString()}</p>
                    </div>
                    <div className={`scan-badge ${scan.status}`}>
                      {scan.status}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="no-data">{t('dashboard.noScans')}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;