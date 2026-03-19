import React from 'react';
import { useTranslation } from 'react-i18next';
import './LogoutModal.css';

function LogoutModal({ isOpen, onConfirm, onCancel }) {
  const { t } = useTranslation();
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
        </div>
        <h2>{t('logout.title')}</h2>
        <p>{t('logout.message')}</p>
        <div className="modal-actions">
          <button onClick={onCancel} className="btn-cancel">
            {t('logout.cancel')}
          </button>
          <button onClick={onConfirm} className="btn-confirm">
            {t('logout.confirm')}
          </button>
        </div>
      </div>
    </div>
  );
}

export default LogoutModal;
