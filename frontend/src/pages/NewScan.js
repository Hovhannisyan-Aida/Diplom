import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTranslation } from 'react-i18next';
import { scansAPI } from '../services/api';
import { Shield, ArrowLeft } from 'lucide-react';
import { useToast } from '../context/ToastContext';
import LogoutModal from '../components/LogoutModal';
import './NewScan.css';

function NewScan() {
  const { t } = useTranslation();
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('full');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const { logout } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await scansAPI.create({
        target_url: targetUrl,
        scan_type: scanType,
      });
      
      showToast(t('toast.scanCreated'), 'success');
      navigate(`/scans/${response.data.id}`);
    } catch (err) {
      showToast(err.response?.data?.detail || t('toast.scanFailed'), 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="new-scan-page">
      <nav className="navbar">
        <div className="navbar-brand">
          <Shield size={24} />
          <span>Vulnerability Scanner</span>
        </div>
        <div className="navbar-menu">
          <button onClick={() => navigate('/dashboard')} className="nav-link">
            {t('nav.dashboard')}
          </button>
          <button onClick={() => navigate('/scans')} className="nav-link">
            {t('nav.scans')}
          </button>
          <button onClick={() => navigate('/new-scan')} className="nav-link active">
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

      <div className="new-scan-content">
        <button onClick={() => navigate('/dashboard')} className="back-button">
          <ArrowLeft size={20} />
          {t('newScan.backToDashboard')}
        </button>

        <div className="new-scan-card">
          <h1>{t('newScan.title')}</h1>
          <p className="subtitle">{t('newScan.subtitle')}</p>

          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="scan-form">
            <div className="form-group">
              <label htmlFor="targetUrl">{t('newScan.targetUrl')} *</label>
              <input
                id="targetUrl"
                type="url"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder={t('newScan.targetUrlPlaceholder')}
                required
              />
              <small>{t('newScan.targetUrlHelp')}</small>
            </div>

            <div className="form-group">
              <label htmlFor="scanType">{t('newScan.scanType')} *</label>
              <div className="custom-select-wrapper">
                <select
                  id="scanType"
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  className="custom-select"
                >
                  <option value="quick">{t('newScan.quickScan')}</option>
                  <option value="full">{t('newScan.fullScan')}</option>
                  <option value="custom">{t('newScan.customScan')}</option>
                </select>
                <div className="select-arrow">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                  </svg>
                </div>
              </div>
            </div>

            <div className="scan-info">
              <h3>{t('newScan.whatWillBeScanned')}</h3>
              <ul>
                <li>{t('newScan.sqlInjection')}</li>
                <li>{t('newScan.xss')}</li>
                <li>{t('newScan.securityHeaders')}</li>
                <li>{t('newScan.commonVulnerabilities')}</li>
              </ul>
            </div>

            <div className="form-actions">
              <button
                type="button"
                onClick={() => navigate('/dashboard')}
                className="btn-secondary"
              >
                {t('newScan.cancel')}
              </button>
              <button
                type="submit"
                className="btn-primary"
                disabled={loading}
              >
                {loading ? t('newScan.creating') : t('newScan.startScan')}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

export default NewScan;