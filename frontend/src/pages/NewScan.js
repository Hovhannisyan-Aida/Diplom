import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTranslation } from 'react-i18next';
import { scansAPI } from '../services/api';
import { Shield, Globe, AlertCircle, Check } from 'lucide-react';
import LogoutModal from '../components/LogoutModal';
import LanguageSwitcher from '../components/LanguageSwitcher';
import ScanningLoader from '../components/ScanningLoader';
import './NewScan.css';

function NewScan() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('full');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const [showLeaveWarning, setShowLeaveWarning] = useState(false);
  const [pendingPath, setPendingPath] = useState(null);

  useEffect(() => {
    if (!loading) return;
    const handler = (e) => { e.preventDefault(); e.returnValue = ''; };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [loading]);

  const safeNavigate = (path) => {
    if (loading) {
      setPendingPath(path);
      setShowLeaveWarning(true);
    } else {
      navigate(path);
    }
  };

  const confirmLeave = () => {
    setShowLeaveWarning(false);
    if (pendingPath) navigate(pendingPath);
  };
  
  const [customOptions, setCustomOptions] = useState({
    sql_injection: true,
    xss: true,
    security_headers: true,
    crypto: true
  });

  const getScanFeatures = () => {
    switch (scanType) {
      case 'full':
        return [
          t('newScan.sqlInjection'),
          t('newScan.xss'),
          t('newScan.securityHeaders'),
          t('newScan.cryptoFailures'),
          t('newScan.commonVulnerabilities')
        ];
      case 'quick':
        return [
          t('newScan.securityHeaders'),
          t('newScan.basicSecurityChecks')
        ];
      case 'custom':
        const features = [];
        if (customOptions.sql_injection) features.push(t('newScan.sqlInjection'));
        if (customOptions.xss) features.push(t('newScan.xss'));
        if (customOptions.security_headers) features.push(t('newScan.securityHeaders'));
        if (customOptions.crypto) features.push(t('newScan.cryptoFailures'));
        return features.length > 0 ? features : [t('newScan.noScannersSelected')];
      default:
        return [];
    }
  };

  const handleCustomOptionChange = (option) => {
    setCustomOptions(prev => ({
      ...prev,
      [option]: !prev[option]
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!targetUrl.trim()) {
      setError(t('newScan.errorEmptyUrl'));
      return;
    }

    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      setError(t('newScan.errorInvalidProtocol'));
      return;
    }

    try {
      new URL(targetUrl);
    } catch {
      setError(t('newScan.errorInvalidUrl'));
      return;
    }

    if (scanType === 'custom') {
      const hasAnySelected = Object.values(customOptions).some(v => v === true);
      if (!hasAnySelected) {
        setError(t('newScan.errorNoScanners'));
        return;
      }
    }

    setLoading(true);

    try {
      const scanData = {
        target_url: targetUrl,
        scan_type: scanType,
        custom_options: {
          ...(scanType === 'custom' ? customOptions : {}),
          language: i18n.language
        }
      };

      const response = await scansAPI.create(scanData);
      navigate(`/scans/${response.data.id}`);
    } catch (err) {
      setError(err.response?.data?.detail || t('newScan.errorCreate'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="new-scan-page">
      {loading && <ScanningLoader url={targetUrl} />}
      <nav className="navbar">
        <div className="navbar-brand">
          <Shield size={24} />
          <span>Vulnerability Scanner</span>
        </div>
        <div className="navbar-menu">
          <button onClick={() => safeNavigate('/dashboard')} className="nav-link">
            {t('nav.dashboard')}
          </button>
          <button onClick={() => safeNavigate('/scans')} className="nav-link">
            {t('nav.scans')}
          </button>
          <button onClick={() => safeNavigate('/new-scan')} className="nav-link nav-link-active">
            {t('nav.newScan')}
          </button>
          <LanguageSwitcher />
          <button onClick={() => loading ? safeNavigate('/login') : setShowLogoutModal(true)} className="btn-logout">
            {t('nav.logout')}
          </button>
        </div>
      </nav>

      {showLeaveWarning && (
        <div className="leave-warning-overlay">
          <div className="leave-warning-card">
            <div className="leave-warning-icon">⚠️</div>
            <h3 className="leave-warning-title">{t('newScan.scanInProgress')}</h3>
            <p className="leave-warning-message">
              {t('newScan.leaveWarning')}
            </p>
            <div className="leave-warning-actions">
              <button className="leave-btn-stay" onClick={() => setShowLeaveWarning(false)}>
                {t('newScan.stayOnPage')}
              </button>
              <button className="leave-btn-leave" onClick={confirmLeave}>
                {t('newScan.leaveAnyway')}
              </button>
            </div>
          </div>
        </div>
      )}

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
        <div className="new-scan-header">
          <h1>{t('newScan.title')}</h1>
          <p>{t('newScan.subtitle')}</p>
        </div>

        <form onSubmit={handleSubmit} className="scan-form">
          <div className="form-group">
            <label htmlFor="targetUrl" className="form-label">
              <Globe size={20} />
              {t('newScan.targetUrl')} *
            </label>
            <input
              type="text"
              id="targetUrl"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              className="form-input"
              disabled={loading}
            />
            <p className="form-help">{t('newScan.targetUrlHelp')}</p>
          </div>

          <div className="form-group">
            <label htmlFor="scanType" className="form-label">
              {t('newScan.scanType')} *
            </label>
            <select
              id="scanType"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="form-select"
              disabled={loading}
            >
              <option value="full">{t('newScan.fullScan')}</option>
              <option value="quick">{t('newScan.quickScan')}</option>
              <option value="custom">{t('newScan.customScan')}</option>
            </select>
          </div>

          {scanType === 'custom' && (
            <div className="custom-scan-options">
              <h3 className="custom-scan-title">{t('newScan.selectScanners')}</h3>
              <div className="scanner-checkboxes">
                <label className="scanner-checkbox">
                  <input
                    type="checkbox"
                    checked={customOptions.sql_injection}
                    onChange={() => handleCustomOptionChange('sql_injection')}
                    disabled={loading}
                  />
                  <span className="checkbox-label">
                    {t('newScan.sqlScanner')}
                  </span>
                  <span className="scanner-description">{t('newScan.sqlScannerDesc')}</span>
                </label>

                <label className="scanner-checkbox">
                  <input
                    type="checkbox"
                    checked={customOptions.xss}
                    onChange={() => handleCustomOptionChange('xss')}
                    disabled={loading}
                  />
                  <span className="checkbox-label">
                    {t('newScan.xssScanner')}
                  </span>
                  <span className="scanner-description">{t('newScan.xssScannerDesc')}</span>
                </label>

                <label className="scanner-checkbox">
                  <input
                    type="checkbox"
                    checked={customOptions.security_headers}
                    onChange={() => handleCustomOptionChange('security_headers')}
                    disabled={loading}
                  />
                  <span className="checkbox-label">
                    {t('newScan.headersScanner')}
                  </span>
                  <span className="scanner-description">{t('newScan.headersScannerDesc')}</span>
                </label>
                <label className="scanner-checkbox">
                  <input
                    type="checkbox"
                    checked={customOptions.crypto}
                    onChange={() => handleCustomOptionChange('crypto')}
                    disabled={loading}
                  />
                  <span className="checkbox-label">
                    {t('newScan.cryptoScanner')}
                  </span>
                  <span className="scanner-description">{t('newScan.cryptoScannerDesc')}</span>
                </label>
              </div>
            </div>
          )}

          <div className="scan-info-box">
            <div className="scan-info-header">
              <Shield size={20} className="scan-info-icon" />
              <h3>{t('newScan.whatWillBeScanned')}</h3>
            </div>
            <ul className="scan-features-list">
              {getScanFeatures().map((feature, index) => (
                <li key={index}>
                  <Check size={20} className="feature-check" />
                  {feature}
                </li>
              ))}
            </ul>
          </div>

          {error && (
            <div className="error-message">
              <AlertCircle size={20} />
              {error}
            </div>
          )}

          <div className="form-actions">
            <button
              type="button"
              onClick={() => safeNavigate('/scans')}
              className="btn-cancel"
              disabled={loading}
            >
              {t('newScan.cancel')}
            </button>
            <button
              type="submit"
              className="btn-submit"
              disabled={loading}
            >
              {loading ? t('newScan.creating') : t('newScan.startScan')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default NewScan;