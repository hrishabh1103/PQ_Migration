import { useState, useCallback } from 'react';

export interface UseInstanceReportReturn {
  selectedAssetId: string | null;
  isOpen: boolean;
  openReport: (assetId: string | null | undefined) => void;
  closeReport: () => void;
}

/**
 * Reusable hook for managing InstanceReportModal state across all 11 UI pages.
 * Enforces canonical backend asset_id resolution before opening the modal.
 */
export function useInstanceReport(): UseInstanceReportReturn {
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  const openReport = useCallback((assetId: string | null | undefined) => {
    if (!assetId) {
      console.warn('InstanceReport requested without valid canonical asset_id');
      return;
    }
    setSelectedAssetId(assetId);
  }, []);

  const closeReport = useCallback(() => {
    setSelectedAssetId(null);
  }, []);

  return {
    selectedAssetId,
    isOpen: selectedAssetId !== null,
    openReport,
    closeReport,
  };
}
