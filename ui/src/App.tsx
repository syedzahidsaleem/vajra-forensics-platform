import React from 'react';
import { AppProvider, useApp } from './context/AppContext';
import { AppShell } from './components/layout/AppShell';
import { ToastProvider } from './components/ui/vajra-components';
import { CaseDashboard } from './screens/CaseDashboard';
import { DeviceSelection } from './screens/DeviceSelection';
import { AcquisitionWizard } from './screens/AcquisitionWizard';
import { SanitizationConsole } from './screens/SanitizationConsole';
import { ReportCenter } from './screens/ReportCenter';
import { RecoveryBrowser } from './screens/RecoveryBrowser';
import { HexExplorer } from './screens/HexExplorer';

import { ThemeProvider } from './context/ThemeContext';

const ScreenRouter: React.FC = () => {
  const { activeScreen } = useApp();

  switch (activeScreen) {
    case 'dashboard':
      return <CaseDashboard />;
    case 'devices':
      return <DeviceSelection />;
    case 'acquisition':
      return <AcquisitionWizard />;
    case 'sanitization':
      return <SanitizationConsole />;
    case 'reports':
    case 'audit':
      return <ReportCenter />;
    case 'recovery':
      return <RecoveryBrowser />;
    case 'hex':
      return <HexExplorer />;
    default:
      return <CaseDashboard />;
  }
};

export const App: React.FC = () => {
  return (
    <ThemeProvider>
      <ToastProvider>
        <AppProvider>
          <AppShell>
            <ScreenRouter />
          </AppShell>
        </AppProvider>
      </ToastProvider>
    </ThemeProvider>
  );
};

export default App;
