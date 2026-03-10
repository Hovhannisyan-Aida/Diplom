import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { scansAPI } from '../services/api';
import { Shield, ArrowLeft } from 'lucide-react';
import LogoutModal from '../components/LogoutModal';
import './NewScan.css';

function NewScan() {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('full');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { logout } = useAuth();
  const [showLogoutModal, setShowLogoutModal] = useState(false);
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
      
      alert('Scan created successfully!');
      navigate(`/scans/${response.data.id}`);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create scan. Please try again.');
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
            Dashboard
          </button>
          <button onClick={() => navigate('/scans')} className="nav-link">
            Scans
          </button>
          <button onClick={() => navigate('/new-scan')} className="nav-link active">
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

      <div className="new-scan-content">
        <button onClick={() => navigate('/dashboard')} className="back-button">
          <ArrowLeft size={20} />
          Back to Dashboard
        </button>

        <div className="new-scan-card">
          <h1>Create New Scan</h1>
          <p className="subtitle">Enter the target URL to scan for vulnerabilities</p>

          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="scan-form">
            <div className="form-group">
              <label htmlFor="targetUrl">Target URL *</label>
              <input
                id="targetUrl"
                type="url"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com"
                required
              />
              <small>Enter the full URL including http:// or https://</small>
            </div>

            <div className="form-group">
              <label htmlFor="scanType">Scan Type *</label>
              <div className="custom-select-wrapper">
                <select
                  id="scanType"
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                  className="custom-select"
                >
                  <option value="quick">Quick Scan - Basic security checks</option>
                  <option value="full">Full Scan - Comprehensive analysis (recommended)</option>
                  <option value="custom">Custom Scan - Advanced options</option>
                </select>
                <div className="select-arrow">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                  </svg>
                </div>
              </div>
            </div>

            <div className="scan-info">
              <h3>What will be scanned?</h3>
              <ul>
                <li>SQL Injection vulnerabilities</li>
                <li>Cross-Site Scripting (XSS)</li>
                <li>Security Headers configuration</li>
                <li>Common web vulnerabilities</li>
              </ul>
            </div>

            <div className="form-actions">
              <button
                type="button"
                onClick={() => navigate('/dashboard')}
                className="btn-secondary"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn-primary"
                disabled={loading}
              >
                {loading ? 'Creating Scan...' : 'Start Scan'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

export default NewScan;