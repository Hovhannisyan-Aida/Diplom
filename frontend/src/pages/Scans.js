import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTranslation } from 'react-i18next';
import { scansAPI } from '../services/api';
import { Shield, Plus } from 'lucide-react';
import LogoutModal from '../components/LogoutModal';
import './Scans.css';

// Helper function - ԴՈՒՐՍՈՒՄ component-ից
const formatDateTime = (dateString) => {
  if (!dateString) return '-';
  
  const date = new Date(dateString);
  
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  });
};

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
        <div className="scans-loading">{t('scans.loading')}</div>
      </div>
    );
  }

  return (
    <div className="scans-page">
      <nav className="scans-navbar">
        <div className="scans-navbar-brand">
          <Shield size={24} />
          <span>Vulnerability Scanner</span>
        </div>
        <div className="scans-navbar-menu">
          <button onClick={() => navigate('/dashboard')} className="scans-nav-link">
            {t('nav.dashboard')}
          </button>
          <button onClick={() => navigate('/scans')} className="scans-nav-link scans-nav-link-active">
            {t('nav.scans')}
          </button>
          <button onClick={() => navigate('/new-scan')} className="scans-nav-link">
            {t('nav.newScan')}
          </button>
          <button onClick={() => setShowLogoutModal(true)} className="scans-btn-logout">
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
            <h1 className="scans-title">{t('scans.title')}</h1>
            <p className="scans-subtitle">{t('scans.subtitle')}</p>
          </div>
          <button onClick={() => navigate('/new-scan')} className="scans-btn-new">
            <Plus size={20} />
            {t('scans.newScan')}
          </button>
        </div>

        {scans.length === 0 ? (
          <div className="scans-no-data">
            <p>{t('scans.noScans')}</p>
            <button onClick={() => navigate('/new-scan')} className="scans-btn-primary">
              {t('scans.createFirst')}
            </button>
          </div>
        ) : (
          <div className="scans-table-wrapper">
            <div style={{width: '100%', overflowX: 'auto'}}>
              <table className="scans-data-table" style={{width: '100%', borderCollapse: 'collapse', tableLayout: 'auto'}}>
                <colgroup>
                  <col style={{width: '25%'}} />
                  <col style={{width: '10%'}} />
                  <col style={{width: '12%'}} />
                  <col style={{width: '20%'}} />
                  <col style={{width: '10%'}} />
                  <col style={{width: '13%'}} />
                  <col style={{width: '10%'}} />
                </colgroup>
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
                      <td className="scans-url-cell">{scan.target_url}</td>
                      <td>
                        <span className="scans-type-badge">{scan.scan_type}</span>
                      </td>
                      <td>
                        <span className={`scans-status-badge scans-status-${scan.status}`}>
                          {scan.status}
                        </span>
                      </td>
                      <td>
                        {scan.total_vulnerabilities > 0 ? (
                          <div className="scans-vuln-summary">
                            {scan.critical_count > 0 && (
                              <span className="scans-vuln-count scans-vuln-critical">
                                C: {scan.critical_count}
                              </span>
                            )}
                            {scan.high_count > 0 && (
                              <span className="scans-vuln-count scans-vuln-high">
                                H: {scan.high_count}
                              </span>
                            )}
                            {scan.medium_count > 0 && (
                              <span className="scans-vuln-count scans-vuln-medium">
                                M: {scan.medium_count}
                              </span>
                            )}
                            {scan.low_count > 0 && (
                              <span className="scans-vuln-count scans-vuln-low">
                                L: {scan.low_count}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="scans-no-vulns">-</span>
                        )}
                      </td>
                      <td>{scan.scan_duration ? `${scan.scan_duration}s` : '-'}</td>
                      <td className="scans-created-cell">
                        {formatDateTime(scan.created_at)}
                      </td>
                      <td>
                        <button
                          onClick={() => navigate(`/scans/${scan.id}`)}
                          className="scans-btn-view"
                        >
                          {t('scans.view')}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Scans;