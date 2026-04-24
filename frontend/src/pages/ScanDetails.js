import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useScan } from '../context/ScanContext';
import { useTranslation } from 'react-i18next';
import { scansAPI } from '../services/api';
import { Shield, Download, ArrowLeft } from 'lucide-react';
import LogoutModal from '../components/LogoutModal';
import LanguageSwitcher from '../components/LanguageSwitcher';
import ScanningLoader from '../components/ScanningLoader';
import './ScanDetails.css';

const POLLING_INTERVAL = 3000;
const ACTIVE_STATUSES = ['pending', 'in_progress'];

const formatDuration = (seconds) => {
  if (!seconds) return '-';
  const total = Math.round(seconds);
  if (total < 60) return `${total}s`;
  const m = Math.floor(total / 60);
  const s = total % 60;
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
};

const formatDateTime = (dateString) => {
  if (!dateString) return '-';
  const utc = dateString.endsWith('Z') || dateString.includes('+') ? dateString : dateString + 'Z';
  const date = new Date(utc);

  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  });
};

function ScanDetails() {
  const { t } = useTranslation();
  const { id } = useParams();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const { addActiveScan } = useScan();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [overlayDismissed, setOverlayDismissed] = useState(false);
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const pollRef = useRef(null);

  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  useEffect(() => {
    loadScanDetails();
    return () => stopPolling();
  }, [id]);

  const loadScanDetails = async () => {
    try {
      const response = await scansAPI.getById(id);
      const data = response.data;
      setScan(data);

      if (ACTIVE_STATUSES.includes(data.status)) {
        if (!pollRef.current) {
          pollRef.current = setInterval(async () => {
            try {
              const pollResponse = await scansAPI.getById(id);
              const updated = pollResponse.data;
              setScan(updated);
              if (!ACTIVE_STATUSES.includes(updated.status)) {
                stopPolling();
              }
            } catch {
              stopPolling();
            }
          }, POLLING_INTERVAL);
        }
      }
    } catch (error) {
      console.error('Failed to load scan details:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRunInBackground = () => {
    if (scan) addActiveScan({ id: scan.id, target_url: scan.target_url });
    setOverlayDismissed(true);
  };

  const handleExportJSON = async () => {
    if (!scan) return;
    try {
      const response = await scansAPI.export(scan.id);
      const dataStr = JSON.stringify(response.data, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `scan-${scan.id}-${new Date().toISOString()}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
    }
  };

  if (loading) {
    return (
      <div className="scan-details-page">
        <div className="loading">{t('scanDetails.loading')}</div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="scan-details-page">
        <div className="error">{t('scanDetails.notFound')}</div>
      </div>
    );
  }

  const criticalCount = scan.critical_count || 0;
  const highCount = scan.high_count || 0;
  const mediumCount = scan.medium_count || 0;
  const lowCount = scan.low_count || 0;

  const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sortedVulnerabilities = [...(scan.vulnerabilities || [])].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
  );

  return (
    <div className="scan-details-page">
      {scan && ACTIVE_STATUSES.includes(scan.status) && !overlayDismissed && (
        <ScanningLoader url={scan.target_url} onBackground={handleRunInBackground} />
      )}
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
        onConfirm={() => {
          setShowLogoutModal(false);
          logout();
          navigate('/login');
        }}
        onCancel={() => setShowLogoutModal(false)}
      />

      <div className="scan-details-content">
        <div className="details-header">
          <div>
            <button onClick={() => navigate('/scans')} className="back-button">
              <ArrowLeft size={20} />
              {t('scanDetails.backToScans')}
            </button>
            <h1>{t('scanDetails.title')}</h1>
          </div>
          <button onClick={handleExportJSON} className="export-button">
            <Download size={20} />
            {t('scanDetails.exportJson')}
          </button>
        </div>

        <div className="scan-info-grid">
          <div className="info-card">
            <div className="info-label">{t('scanDetails.status')}</div>
            <div className={`status-badge status-${scan.status}`}>
              {t(`status.${scan.status}`)}
            </div>
          </div>

          <div className="info-card">
            <div className="info-label">{t('scanDetails.scanType')}</div>
            <div className="info-value">{t(`scanType.${scan.scan_type}`)}</div>
          </div>

          <div className="info-card">
            <div className="info-label">{t('scanDetails.duration')}</div>
            <div className="info-value">
              {formatDuration(scan.scan_duration)}
            </div>
          </div>

          <div className="info-card">
            <div className="info-label">{t('scanDetails.created')}</div>
            <div className="info-value">
              {formatDateTime(scan.created_at)}
            </div>
          </div>
        </div>

        <div className="url-card">
          <div className="url-label">{t('scanDetails.targetUrl')}</div>
          <div className="url-value">{scan.target_url}</div>
        </div>

        <div className="vulnerabilities-summary">
          <h2>{t('scanDetails.vulnerabilitiesSummary')}</h2>
          <div className="summary-grid">
            <div className="summary-card critical">
              <div className="summary-count">{criticalCount}</div>
              <div className="summary-label">{t('scanDetails.critical')}</div>
            </div>
            <div className="summary-card high">
              <div className="summary-count">{highCount}</div>
              <div className="summary-label">{t('scanDetails.high')}</div>
            </div>
            <div className="summary-card medium">
              <div className="summary-count">{mediumCount}</div>
              <div className="summary-label">{t('scanDetails.medium')}</div>
            </div>
            <div className="summary-card low">
              <div className="summary-count">{lowCount}</div>
              <div className="summary-label">{t('scanDetails.low')}</div>
            </div>
          </div>
        </div>

        <div className="vulnerabilities-list">
          <h2>{t('scanDetails.vulnerabilitiesList')}</h2>
          {sortedVulnerabilities.length > 0 ? (
            <div className="vulnerabilities">
              {sortedVulnerabilities.map((vuln, index) => (
                <div key={index} className={`vulnerability-card severity-${vuln.severity}`}>
                  <div className="vuln-header">
                    <h3>{vuln.title}</h3>
                    <span className={`severity-badge ${vuln.severity}`}>
                      {vuln.severity}
                    </span>
                  </div>
                  <div className="vuln-details">
                    <div className="vuln-detail">
                      <strong>{t('scanDetails.url')}:</strong> {vuln.url}
                    </div>
                    {vuln.parameter && (
                      <div className="vuln-detail">
                        <strong>{t('scanDetails.parameter')}:</strong> {vuln.parameter}
                      </div>
                    )}
                    {vuln.method && (
                      <div className="vuln-detail">
                        <strong>{t('scanDetails.method')}:</strong> {vuln.method}
                      </div>
                    )}
                    <div className="vuln-description">{vuln.description}</div>
                    {vuln.recommendation && (
                      <div className="vuln-recommendation">
                        <strong>{t('scanDetails.recommendation')}:</strong> {vuln.recommendation}
                      </div>
                    )}
                    {vuln.references && (
                      <div className="vuln-reference">
                        <a href={vuln.references} target="_blank" rel="noopener noreferrer">
                          {t('scanDetails.learnMore')} →
                        </a>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="no-vulnerabilities">
              {t('scanDetails.noVulnerabilities')}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ScanDetails;