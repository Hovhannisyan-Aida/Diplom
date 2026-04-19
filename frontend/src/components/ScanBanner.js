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
        <span className="scan-banner-text">
          {activeScans.length === 1
            ? t('scanBanner.single', { url: activeScans[0].target_url })
            : t('scanBanner.multiple', { count: activeScans.length })}
        </span>
        {activeScans.length === 1 && (
          <button
            className="scan-banner-link"
            onClick={() => navigate(`/scans/${activeScans[0].id}`)}
          >
            {t('scanBanner.view')}
          </button>
        )}
      </div>
    </div>
  );
}

export default ScanBanner;
