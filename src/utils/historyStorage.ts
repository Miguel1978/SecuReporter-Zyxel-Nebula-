import { AnalysisHistoryItem } from '../types';

const STORAGE_KEY = 'nebulaguard_analysis_history';
const MAX_HISTORY = 10;

export function getStoredAnalysisHistory(): AnalysisHistoryItem[] {
  if (typeof window === 'undefined' || !window.localStorage) {
    return [];
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.warn('Erreur lecture historique localStorage:', err);
    return [];
  }
}

export function saveAnalysisToHistory(
  item: Omit<AnalysisHistoryItem, 'id' | 'timestamp'>
): AnalysisHistoryItem[] {
  if (typeof window === 'undefined' || !window.localStorage) {
    return [];
  }

  try {
    const existing = getStoredAnalysisHistory();

    const newItem: AnalysisHistoryItem = {
      id: `hist-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      ...item,
    };

    // Filter out if exact same title and riskScore to avoid redundant consecutive saves
    const filtered = existing.filter(
      (h) => !(h.title === newItem.title && h.riskScore === newItem.riskScore && h.rawLogs === newItem.rawLogs)
    );

    const updated = [newItem, ...filtered].slice(0, MAX_HISTORY);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.warn('Erreur sauvegarde historique localStorage:', err);
    return [];
  }
}

export function deleteHistoryItem(id: string): AnalysisHistoryItem[] {
  if (typeof window === 'undefined' || !window.localStorage) {
    return [];
  }

  try {
    const existing = getStoredAnalysisHistory();
    const updated = existing.filter((item) => item.id !== id);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.warn('Erreur suppression item historique:', err);
    return [];
  }
}

export function clearAnalysisHistory(): void {
  if (typeof window === 'undefined' || !window.localStorage) {
    return;
  }

  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    console.warn('Erreur effacement historique:', err);
  }
}
