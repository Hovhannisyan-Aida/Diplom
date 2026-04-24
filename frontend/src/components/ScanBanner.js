import React from 'react';
import { useScan } from '../context/ScanContext';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import './ScanBanner.css';

function ScanBanner() {
  const { activeScans } = useScan();
  const { t } = useTranslation();
  const navigate = useNavigate();

  if (activeScans.length === 0) return null;

  return (
    <div className="scan-banner">
      <div className="scan-banner-inner">
        <span className="scan-banner-spinner" />
        <div className="scan-banner-body">
          {activeScans.length === 1 ? (
            <span className="scan-banner-text">
              {t('scanBanner.single', { url: activeScans[0].target_url })}
            </span>
          ) : (
            <span className="scan-banner-text">
              {t('scanBanner.multiple', { count: activeScans.length })}
              {': '}
              {activeScans.map((s) => s.target_url).join(', ')}
            </span>
          )}
          <button
            className="scan-banner-link"
            onClick={() =>
              activeScans.length === 1
                ? navigate(`/scans/${activeScans[0].id}`)
                : navigate('/scans')
            }
          >
            {t('scanBanner.view')}
          </button>
        </div>
      </div>
    </div>
  );
}

export default ScanBanner;
