import React from 'react';
import { useTranslation } from 'react-i18next';
import { Shield } from 'lucide-react';
import './ScanningLoader.css';

function ScanningLoader({ url }) {
  const { t } = useTranslation();
  return (
    <div className="scanning-overlay">
      <div className="scanning-card">

        <div className="scanning-icon-wrap">
          <Shield size={48} className="scanning-icon" />
          <div className="scanning-beam" />
        </div>

        <div className="scanning-text">
          {t('newScan.scanning')}<span className="dots"><span>.</span><span>.</span><span>.</span></span>
        </div>

        {url && <div className="scanning-url">{url}</div>}

      </div>
    </div>
  );
}

export default ScanningLoader;
