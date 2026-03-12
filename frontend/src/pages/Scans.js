import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTranslation } from 'react-i18next';
import { scansAPI } from '../services/api';
import { Shield, Plus } from 'lucide-react';
import LogoutModal from '../components/LogoutModal';
import './Scans.css';

function Scans() {
  const { t } = useTranslation();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const { logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    try {
      const response = await scansAPI.getAll();
      setScans(response.data);
    } catch (error) {
      console.error('Failed to load scans:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="scans-page">
        <div className="loading">{t('scans.loading')}</div>
      </div>
    );
  }

  return (
    <div className="scans-page">
      <nav className="navbar">
        <div className="navbar-brand">
          <Shield size={24} />
          <span>Vulnerability Scanner</span>
        </div>
        <div className="navbar-menu">
          <button onClick={() => navigate('/dashboard')} className="nav-link">
            {t('nav.dashboard')}
          </button>
          <button onClick={() => navigate('/scans')} className="nav-link active">
            {t('nav.scans')}
          </button>
          <button onClick={() => navigate('/new-scan')} className="nav-link">
            {t('nav.newScan')}
          </button>
          <button onClick={() => setShowLogoutModal(true)} className="btn-logout">
            {t('nav.logout')}
          </button>
        </div>
      </nav>

      <LogoutModal 
        isOpen={showLogoutModal}
        onConfirm={() => {
          setShowLogoutModal(false);
          logout();
          navigate('/login');
        }}
        onCancel={() => setShowLogoutModal(false)}
      />

      <div className="scans-content">
        <div className="scans-header">
          <div>
            <h1>{t('scans.title')}</h1>
            <p>{t('scans.subtitle')}</p>
          </div>
          <button onClick={() => navigate('/new-scan')} className="btn-new-scan">
            <Plus size={20} />
            {t('scans.newScan')}
          </button>
        </div>

        {scans.length === 0 ? (
          <div className="no-scans">
            <p>{t('scans.noScans')}</p>
            <button onClick={() => navigate('/new-scan')} className="btn-primary">
              {t('scans.createFirst')}
            </button>
          </div>
        ) : (
          <div className="scans-table-container">
            <table className="scans-table">
              <thead>
                <tr>
                  <th>{t('scans.targetUrl')}</th>
                  <th>{t('scans.type')}</th>
                  <th>{t('scans.status')}</th>
                  <th>{t('scans.vulnerabilities')}</th>
                  <th>{t('scans.duration')}</th>
                  <th>{t('scans.created')}</th>
                  <th>{t('scans.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td style={{backgroundColor: '#ffcccc'}}>{scan.target_url || 'EMPTY'}</td>
                    <td style={{backgroundColor: '#ccffcc'}}>
                      <span className="type-badge">{scan.scan_type || 'EMPTY'}</span>
                    </td>
                    <td style={{backgroundColor: '#ccccff'}}>
                      <span className={`status-badge status-${scan.status}`}>
                        {scan.status || 'EMPTY'}
                      </span>
                    </td>
                    <td>
                      {scan.total_vulnerabilities > 0 ? (
                        <div className="vuln-summary">
                          {scan.critical_count > 0 && (
                            <span className="vuln-count critical">
                              C: {scan.critical_count}
                            </span>
                          )}
                          {scan.high_count > 0 && (
                            <span className="vuln-count high">
                              H: {scan.high_count}
                            </span>
                          )}
                          {scan.medium_count > 0 && (
                            <span className="vuln-count medium">
                              M: {scan.medium_count}
                            </span>
                          )}
                          {scan.low_count > 0 && (
                            <span className="vuln-count low">
                              L: {scan.low_count}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="no-vulns">-</span>
                      )}
                    </td>
                    <td>{scan.scan_duration ? `${scan.scan_duration}s` : '-'}</td>
                    <td>{new Date(scan.created_at).toLocaleDateString()}</td>
                    <td>
                      <button
                        onClick={() => navigate(`/scans/${scan.id}`)}
                        className="btn-view"
                      >
                        {t('scans.view')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default Scans;