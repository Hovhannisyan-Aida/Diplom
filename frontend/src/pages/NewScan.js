import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTranslation } from 'react-i18next';
import { scansAPI } from '../services/api';
import { Shield, Globe, AlertCircle, Check } from 'lucide-react';
import LogoutModal from '../components/LogoutModal';
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
  
  // Custom scan options
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
          'SQL Injection vulnerabilities',
          'Cross-Site Scripting (XSS)',
          'Security Headers configuration',
          'Cryptographic Failures (SSL/TLS)',
          'Common web vulnerabilities'
        ];
      case 'quick':
        return [
          'Security Headers configuration',
          'Basic security checks'
        ];
      case 'custom':
        const features = [];
        if (customOptions.sql_injection) features.push('SQL Injection vulnerabilities');
        if (customOptions.xss) features.push('Cross-Site Scripting (XSS)');
        if (customOptions.security_headers) features.push('Security Headers configuration');
        if (customOptions.crypto) features.push('Cryptographic Failures (SSL/TLS)');
        return features.length > 0 ? features : ['No scanners selected'];
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
      setError('Please enter a target URL');
      return;
    }

    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      setError('URL must start with http:// or https://');
      return;
    }

    try {
      new URL(targetUrl);
    } catch {
      setError('Invalid URL format');
      return;
    }

    // Validate custom scan has at least one scanner selected
    if (scanType === 'custom') {
      const hasAnySelected = Object.values(customOptions).some(v => v === true);
      if (!hasAnySelected) {
        setError('Please select at least one scanner for custom scan');
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
      setError(err.response?.data?.detail || 'Failed to create scan');
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
          <button onClick={() => navigate('/new-scan')} className="nav-link nav-link-active">
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
            <p className="form-help">Enter the full URL including http:// or https://</p>
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
              <option value="full">Full Scan - Comprehensive analysis (recommended)</option>
              <option value="quick">Quick Scan - Basic security checks</option>
              <option value="custom">Custom Scan - Choose specific scanners</option>
            </select>
          </div>

          {scanType === 'custom' && (
            <div className="custom-scan-options">
              <h3 className="custom-scan-title">Select Scanners:</h3>
              <div className="scanner-checkboxes">
                <label className="scanner-checkbox">
                  <input
                    type="checkbox"
                    checked={customOptions.sql_injection}
                    onChange={() => handleCustomOptionChange('sql_injection')}
                    disabled={loading}
                  />
                  <span className="checkbox-label">
                    SQL Injection Scanner
                  </span>
                  <span className="scanner-description">Tests for SQL injection vulnerabilities in parameters</span>
                </label>
                          
                <label className="scanner-checkbox">
                  <input
                    type="checkbox"
                    checked={customOptions.xss}
                    onChange={() => handleCustomOptionChange('xss')}
                    disabled={loading}
                  />
                  <span className="checkbox-label">
                    XSS Scanner
                  </span>
                  <span className="scanner-description">Tests for Cross-Site Scripting vulnerabilities</span>
                </label>
                          
                <label className="scanner-checkbox">
                  <input
                    type="checkbox"
                    checked={customOptions.security_headers}
                    onChange={() => handleCustomOptionChange('security_headers')}
                    disabled={loading}
                  />
                  <span className="checkbox-label">
                    Security Headers Scanner
                  </span>
                  <span className="scanner-description">Checks for missing security headers</span>
                </label>
                <label className="scanner-checkbox">
                  <input
                    type="checkbox"
                    checked={customOptions.crypto}
                    onChange={() => handleCustomOptionChange('crypto')}
                    disabled={loading}
                  />
                  <span className="checkbox-label">
                    Cryptographic Failures Scanner
                  </span>
                  <span className="scanner-description">Checks for SSL/TLS issues and weak cryptography</span>
                </label>
              </div>
            </div>
          )}

          <div className="scan-info-box">
            <div className="scan-info-header">
              <Shield size={20} className="scan-info-icon" />
              <h3>What will be scanned?</h3>
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
              onClick={() => navigate('/scans')}
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
              {loading ? t('newScan.starting') : t('newScan.startScan')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default NewScan;