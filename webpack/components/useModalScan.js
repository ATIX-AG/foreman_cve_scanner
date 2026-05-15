/* eslint-disable import/no-unresolved */
import { useState } from 'react';

const useModalScan = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [filter, setFilter] = useState('all');

  const openModal = (nextScanId, nextFilter) => {
    setScanId(nextScanId);
    setFilter(nextFilter || 'all');
    setIsOpen(true);
  };

  const closeModal = () => setIsOpen(false);

  return {
    isOpen,
    scanId,
    filter,
    openModal,
    closeModal,
  };
};

export default useModalScan;
