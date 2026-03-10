import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { scansAPI } from '../services/api';
import { Shield, Plus, Eye } from 'lucide-react';
import LogoutModal from '../components/LogoutModal';
import './Scans.css';

function Scans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const { logout } = useAuth();
  const [showLogoutModal, setShowLogoutModal] = useState(false);
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

  const getStatusClass = (status) => {
    return `status-badge status-${status}`;
  };

  return (
    <div className="scans-page">
      <nav className="navbar">
        <div className="navbar-brand">
          <Shield size={24} />
          <span>Vulnerability Scanner</span>
        </div>
        <div className="navbar-menu">
          <button onClick={() => navigate('/dashboard')} className="nav-link">
            Dashboard
          </button>
          <button onClick={() => navigate('/scans')} className="nav-link active">
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

      <div className="scans-content">
        <div className="scans-header">
          <div>
            <h1>All Scans</h1>
            <p>View and manage your security scans</p>
          </div>
          <button onClick={() => navigate('/new-scan')} className="btn-new-scan">
            <Plus size={20} />
            New Scan
          </button>
        </div>

        {loading ? (
          <div className="loading">Loading scans...</div>
        ) : scans.length > 0 ? (
          <div className="scans-table-container">
            <table className="scans-table">
              <thead>
                <tr>
                  <th>Target URL</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Vulnerabilities</th>
                  <th>Duration</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="url-cell">{scan.target_url}</td>
                    <td>
                      <span className="type-badge">{scan.scan_type}</span>
                    </td>
                    <td>
                      <span className={getStatusClass(scan.status)}>
                        {scan.status}
                      </span>
                    </td>
                    <td>
                      <div className="vuln-summary">
                        {scan.critical_count > 0 && (
                          <span className="vuln-count critical">{scan.critical_count}C</span>
                        )}
                        {scan.high_count > 0 && (
                          <span className="vuln-count high">{scan.high_count}H</span>
                        )}
                        {scan.medium_count > 0 && (
                          <span className="vuln-count medium">{scan.medium_count}M</span>
                        )}
                        {scan.low_count > 0 && (
                          <span className="vuln-count low">{scan.low_count}L</span>
                        )}
                        {scan.total_vulnerabilities === 0 && (
                          <span className="no-vulns">None</span>
                        )}
                      </div>
                    </td>
                    <td>{scan.scan_duration || 0}s</td>
                    <td>{new Date(scan.created_at).toLocaleDateString()}</td>
                    <td>
                      <button
                        onClick={() => navigate(`/scans/${scan.id}`)}
                        className="btn-view"
                        title="View Details"
                      >
                        <Eye size={18} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="no-scans">
            <p>No scans yet</p>
            <button onClick={() => navigate('/new-scan')} className="btn-primary">
              Create Your First Scan
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default Scans;