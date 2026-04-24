import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import { scansAPI } from '../services/api';
import { useToast } from './ToastContext';
import { useTranslation } from 'react-i18next';

const ScanContext = createContext();

export const useScan = () => useContext(ScanContext);

const STORAGE_KEY = 'activeScans';

function loadFromStorage() {
  try {
    const data = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
    if (!Array.isArray(data) || !data.every(s => s && typeof s.id === 'number' && typeof s.target_url === 'string')) {
      localStorage.removeItem(STORAGE_KEY);
      return [];
    }
    return data;
  } catch {
    localStorage.removeItem(STORAGE_KEY);
    return [];
  }
}

export const ScanProvider = ({ children }) => {
  const [activeScans, setActiveScans] = useState(loadFromStorage);
  const { showToast } = useToast();
  const { t } = useTranslation();
  const intervalRef = useRef(null);

  const addActiveScan = useCallback((scan) => {
    setActiveScans((prev) => {
      const next = [...prev.filter((s) => s.id !== scan.id), {
        id: scan.id,
        target_url: scan.target_url,
        status: 'pending',
      }];
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const pollScans = useCallback(async () => {
    setActiveScans((prev) => {
      if (prev.length === 0) return prev;
      return prev;
    });

    const current = loadFromStorage();
    if (current.length === 0) return;

    const results = await Promise.all(
      current.map(async (scan) => {
        try {
          const res = await scansAPI.getById(scan.id);
          return { ...scan, status: res.data.status, total_vulnerabilities: res.data.total_vulnerabilities };
        } catch (err) {
          // Server responded (4xx/5xx): scan is gone or broken — treat as failed so it clears
          if (err.response) {
            return { ...scan, status: 'failed' };
          }
          // Pure network error: keep polling
          return scan;
        }
      })
    );

    const stillActive = [];
    results.forEach((scan) => {
      if (scan.status === 'completed') {
        showToast(
          t('scanBanner.toastDone', { url: scan.target_url, count: scan.total_vulnerabilities ?? 0 }),
          'success'
        );
      } else if (scan.status === 'failed') {
        showToast(t('scanBanner.toastFailed', { url: scan.target_url }), 'error');
      } else {
        stillActive.push(scan);
      }
    });

    localStorage.setItem(STORAGE_KEY, JSON.stringify(stillActive));
    setActiveScans(stillActive);
  }, [showToast, t]);

  useEffect(() => {
    clearInterval(intervalRef.current);
    if (activeScans.length > 0) {
      intervalRef.current = setInterval(pollScans, 3000);
    }
    return () => clearInterval(intervalRef.current);
  }, [activeScans.length, pollScans]);

  return (
    <ScanContext.Provider value={{ activeScans, addActiveScan }}>
      {children}
    </ScanContext.Provider>
  );
};
