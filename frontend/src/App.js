import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { AuthProvider, LanguageProvider, useAuth } from './contexts/AppContext';
import { Toaster } from './components/ui/sonner';
import { useEffect, useState } from 'react';
import MainLayout from './layouts/MainLayout';
import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import TargetsPage from './pages/TargetsPage';
import ScansPage from './pages/ScansPage';
import NewScanPage from './pages/NewScanPage';
import ScanDetailPage from './pages/ScanDetailPage';
import ReportsPage from './pages/ReportsPage';
import UsersPage from './pages/UsersPage';
import SettingsPage from './pages/SettingsPage';
import CVEDatabasePage from './pages/CVEDatabasePage';
import AgentsPage from './pages/AgentsPage';
import { Loader2 } from 'lucide-react';

// Theme Provider
const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'light') {
      root.classList.add('light');
    } else {
      root.classList.remove('light');
    }
  }, [theme]);

  // Listen for theme changes from localStorage
  useEffect(() => {
    const handleStorage = () => {
      const newTheme = localStorage.getItem('theme') || 'dark';
      setTheme(newTheme);
    };
    window.addEventListener('storage', handleStorage);
    
    // Also check periodically for same-window changes
    const interval = setInterval(() => {
      const currentTheme = localStorage.getItem('theme') || 'dark';
      if (currentTheme !== theme) {
        setTheme(currentTheme);
      }
    }, 100);
    
    return () => {
      window.removeEventListener('storage', handleStorage);
      clearInterval(interval);
    };
  }, [theme]);

  return children;
};

// Protected Route wrapper
const ProtectedRoute = ({ children, roles }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (roles && !roles.includes(user.role)) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

// Layout wrapper for protected routes
const ProtectedLayout = () => {
  return (
    <ProtectedRoute>
      <MainLayout>
        <Outlet />
      </MainLayout>
    </ProtectedRoute>
  );
};

// Public Route wrapper (redirect if logged in)
const PublicRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

function AppRoutes() {
  return (
    <Routes>
      {/* Public Landing Page */}
      <Route path="/" element={<LandingPage />} />
      
      {/* Login Page */}
      <Route
        path="/login"
        element={
          <PublicRoute>
            <LoginPage />
          </PublicRoute>
        }
      />

      {/* Protected routes */}
      <Route element={<ProtectedLayout />}>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/scans/new" element={<NewScanPage />} />
        <Route path="/scans/:id" element={<ScanDetailPage />} />
        <Route path="/agents" element={
          <ProtectedRoute roles={['admin', 'customer']}>
            <AgentsPage />
          </ProtectedRoute>
        } />
        <Route path="/reports" element={<ReportsPage />} />
        <Route
          path="/users"
          element={
            <ProtectedRoute roles={['admin', 'reseller']}>
              <UsersPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings"
          element={
            <ProtectedRoute roles={['admin', 'reseller']}>
              <SettingsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/cve-database"
          element={
            <ProtectedRoute roles={['admin']}>
              <CVEDatabasePage />
            </ProtectedRoute>
          }
        />
      </Route>
      
      {/* 404 - Redirect to landing */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <LanguageProvider>
          <AuthProvider>
            <AppRoutes />
            <Toaster position="top-right" richColors />
          </AuthProvider>
        </LanguageProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}

export default App;
