import React, { createContext, useContext, useState, useEffect } from 'react';
import { AppMode, ScreenId, CaseRecord, DeviceDescriptor } from '../types';
import { tauriApi } from '../api/tauri';

interface AppContextType {
  mode: AppMode;
  setMode: (mode: AppMode) => void;
  activeScreen: ScreenId;
  setActiveScreen: (screen: ScreenId) => void;
  activeCase: CaseRecord | null;
  setActiveCase: (c: CaseRecord | null) => void;
  selectedDevice: DeviceDescriptor | null;
  setSelectedDevice: (d: DeviceDescriptor | null) => void;
  cases: CaseRecord[];
  devices: DeviceDescriptor[];
  refreshCases: () => Promise<void>;
  refreshDevices: () => Promise<void>;
  pendingModeSwitch: AppMode | null;
  setPendingModeSwitch: (mode: AppMode | null) => void;
  confirmModeSwitch: () => void;
  cancelModeSwitch: () => void;
  targetHexLba: number;
  setTargetHexLba: (lba: number) => void;
  jumpToHexLba: (lba: number) => void;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mode, setModeState] = useState<AppMode>('forensic');
  const [activeScreen, setActiveScreenState] = useState<ScreenId>('dashboard');
  const [activeCase, setActiveCase] = useState<CaseRecord | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<DeviceDescriptor | null>(null);
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [devices, setDevices] = useState<DeviceDescriptor[]>([]);
  const [pendingModeSwitch, setPendingModeSwitch] = useState<AppMode | null>(null);
  const [targetHexLba, setTargetHexLba] = useState<number>(2048);

  const refreshCases = async () => {
    try {
      const list = await tauriApi.listCases();
      setCases(list);
      if (!activeCase && list.length > 0) {
        setActiveCase(list[0]);
      }
    } catch (err) {
      console.error('Failed to load cases:', err);
    }
  };

  const refreshDevices = async () => {
    try {
      const list = await tauriApi.listDevices();
      setDevices(list);
    } catch (err) {
      console.error('Failed to load devices:', err);
    }
  };

  useEffect(() => {
    refreshCases();
    refreshDevices();
  }, []);

  const setActiveScreen = (screen: ScreenId) => {
    // If switching to sanitization console directly, adjust mode
    if (screen === 'sanitization' && mode !== 'sanitization') {
      setPendingModeSwitch('sanitization');
      return;
    }
    setActiveScreenState(screen);
  };

  const jumpToHexLba = (lba: number) => {
    setTargetHexLba(lba);
    setActiveScreen('hex');
  };

  const setMode = (newMode: AppMode) => {
    if (newMode === mode) return;
    if (newMode === 'sanitization') {
      setPendingModeSwitch('sanitization');
    } else {
      setModeState('forensic');
      if (activeScreen === 'sanitization') {
        setActiveScreenState('dashboard');
      }
    }
  };

  const confirmModeSwitch = () => {
    if (pendingModeSwitch) {
      setModeState(pendingModeSwitch);
      if (pendingModeSwitch === 'sanitization') {
        setActiveScreenState('sanitization');
      } else {
        setActiveScreenState('dashboard');
      }
      setPendingModeSwitch(null);
    }
  };

  const cancelModeSwitch = () => {
    setPendingModeSwitch(null);
  };

  return (
    <AppContext.Provider
      value={{
        mode,
        setMode,
        activeScreen,
        setActiveScreen,
        activeCase,
        setActiveCase,
        selectedDevice,
        setSelectedDevice,
        cases,
        devices,
        refreshCases,
        refreshDevices,
        pendingModeSwitch,
        setPendingModeSwitch,
        confirmModeSwitch,
        cancelModeSwitch,
        targetHexLba,
        setTargetHexLba,
        jumpToHexLba,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
};
