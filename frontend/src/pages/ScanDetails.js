import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { scansAPI } from '../services/api';
import { Shield, ArrowLeft, Download, AlertCircle, CheckCircle, Clock } from 'lucide-react';
import LogoutModal from '../components/LogoutModal';
import './ScanDetails.css';

function ScanDetails() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const { logout } = useAuth();
  const [showLogoutModal, setShowLogoutModal] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    loadScanDetails();
  }, [id]);

  const loadScanDetails = async () => {
    try {
      const [scanResponse, vulnResponse] = await Promise.all([
        scansAPI.getById(id),
        scansAPI.getVulnerabilities(id),
      ]);
      setScan(scanResponse.data);
      setVulnerabilities(vulnResponse.data);
    } catch (error) {
      console.error('Failed to load scan details:', error);
      alert('Failed to load scan details');
      navigate('/dashboard');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async () => {
    try {
      const response = await scansAPI.export(id);
      const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan_${id}_vulnerabilities.json`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export:', error);
      alert('Failed to export scan results');
    }
  };

  if (loading) {
    return (
      <div className="scan-details-page">
        <div className="loading">Loading scan details...</div>
      </div>
    );
  }

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#f59e0b',
      low: '#84cc16',
      info: '#3b82f6',
    };
    return colors[severity] || '#64748b';
  };

  const getSeverityBadgeClass = (severity) => {
    return `severity-badge severity-${severity}`;
  };

  return (
    <div className="scan-details-page">
      <nav className="navbar">
        <div className="navbar-brand">
          <Shield size={24} />
          <span>Vulnerability Scanner</span>
        </div>
        <div className="navbar-menu">
          <button onClick={() => navigate('/dashboard')} className="nav-link">
            Dashboard
          </button>
          <button onClick={() => navigate('/scans')} className="nav-link">
            Scans
          </button>
          <button onClick={() => navigate('/new-scan')} className="nav-link">
            New Scan
          </button>
          <button onClick={() => setShowLogoutModal(true)} className="btn-logout">
            Logout
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
        <button onClick={() => navigate('/dashboard')} className="back-button">
          <ArrowLeft size={20} />
          Back to Dashboard
        </button>

        <div className="scan-header">
          <div>
            <h1>Scan Results</h1>
            <p className="scan-url">{scan.target_url}</p>
          </div>
          <button onClick={handleExport} className="btn-export">
            <Download size={18} />
            Export JSON
          </button>
        </div>

        <div className="scan-info-grid">
          <div className="info-card">
            <div className="info-label">Status</div>
            <div className={`status-badge status-${scan.status}`}>
              {scan.status}
            </div>
          </div>
          <div className="info-card">
            <div className="info-label">Scan Type</div>
            <div className="info-value">{scan.scan_type}</div>
          </div>
          <div className="info-card">
            <div className="info-label">Duration</div>
            <div className="info-value">{scan.scan_duration || 0}s</div>
          </div>
          <div className="info-card">
            <div className="info-label">Created</div>
            <div className="info-value">
              {new Date(scan.created_at).toLocaleString()}
            </div>
          </div>
        </div>

        <div className="vulnerabilities-summary">
          <h2>Vulnerabilities Summary</h2>
          <div className="summary-grid">
            <div className="summary-item">
              <div className="summary-count" style={{ color: '#dc2626' }}>
                {scan.critical_count}
              </div>
              <div className="summary-label">Critical</div>
            </div>
            <div className="summary-item">
              <div className="summary-count" style={{ color: '#ea580c' }}>
                {scan.high_count}
              </div>
              <div className="summary-label">High</div>
            </div>
            <div className="summary-item">
              <div className="summary-count" style={{ color: '#f59e0b' }}>
                {scan.medium_count}
              </div>
              <div className="summary-label">Medium</div>
            </div>
            <div className="summary-item">
              <div className="summary-count" style={{ color: '#84cc16' }}>
                {scan.low_count}
              </div>
              <div className="summary-label">Low</div>
            </div>
          </div>
        </div>

        <div className="vulnerabilities-list">
          <h2>Vulnerabilities ({vulnerabilities.length})</h2>
          {vulnerabilities.length > 0 ? (
            <div className="vuln-cards">
              {vulnerabilities.map((vuln) => (
                <div key={vuln.id} className="vuln-card">
                  <div className="vuln-header">
                    <h3>{vuln.title}</h3>
                    <span className={getSeverityBadgeClass(vuln.severity)}>
                      {vuln.severity}
                    </span>
                  </div>
                  <p className="vuln-description">{vuln.description}</p>
                  <div className="vuln-details">
                    <div className="vuln-detail-item">
                      <strong>Type:</strong> {vuln.vuln_type}
                    </div>
                    <div className="vuln-detail-item">
                      <strong>URL:</strong> {vuln.url}
                    </div>
                    {vuln.parameter && (
                      <div className="vuln-detail-item">
                        <strong>Parameter:</strong> {vuln.parameter}
                      </div>
                    )}
                    {vuln.method && (
                      <div className="vuln-detail-item">
                        <strong>Method:</strong> {vuln.method}
                      </div>
                    )}
                  </div>
                  <div className="vuln-recommendation">
                    <strong>Recommendation:</strong>
                    <p>{vuln.recommendation}</p>
                  </div>
                  {vuln.references && (
                    <div className="vuln-references">
                      <a href={vuln.references} target="_blank" rel="noopener noreferrer">
                        Learn more →
                      </a>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="no-vulnerabilities">
              <CheckCircle size={48} style={{ color: '#16a34a' }} />
              <p>No vulnerabilities found</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ScanDetails;