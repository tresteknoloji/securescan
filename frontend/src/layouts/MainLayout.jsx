import { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Button } from '../components/ui/button';
import { ScrollArea } from '../components/ui/scroll-area';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../components/ui/dropdown-menu';
import {
  Shield,
  LayoutDashboard,
  Target,
  Radar,
  FileText,
  Users,
  Settings,
  ChevronLeft,
  ChevronRight,
  LogOut,
  User,
  Globe,
  Menu,
  Moon,
  Sun,
} from 'lucide-react';
import { cn } from '../lib/utils';

const navItems = [
  { key: 'dashboard', icon: LayoutDashboard, path: '/dashboard', roles: ['admin', 'reseller', 'customer'] },
  { key: 'targets', icon: Target, path: '/targets', roles: ['admin', 'reseller', 'customer'] },
  { key: 'scans', icon: Radar, path: '/scans', roles: ['admin', 'reseller', 'customer'] },
  { key: 'reports', icon: FileText, path: '/reports', roles: ['admin', 'reseller', 'customer'] },
  { key: 'users', icon: Users, path: '/users', roles: ['admin', 'reseller'] },
  { key: 'settings', icon: Settings, path: '/settings', roles: ['admin', 'reseller'] },
];

export const MainLayout = ({ children }) => {
  const { user, logout } = useAuth();
  const { t, language, changeLanguage } = useLanguage();
  const location = useLocation();
  const navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');

  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
  }, [theme]);

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    localStorage.setItem('theme', newTheme);
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const filteredNavItems = navItems.filter(item => item.roles.includes(user?.role || 'customer'));

  return (
    <div className={`min-h-screen flex ${theme === 'light' ? 'bg-gray-50' : 'bg-background'}`} data-testid="main-layout">
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed lg:static inset-y-0 left-0 z-50 flex flex-col border-r transition-all duration-300',
          theme === 'light' ? 'border-gray-200 bg-white' : 'border-border bg-card',
          collapsed ? 'w-16' : 'w-64',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        )}
        data-testid="sidebar"
      >
        {/* Logo */}
        <div className={`flex items-center justify-between h-16 px-4 border-b ${theme === 'light' ? 'border-gray-200' : 'border-border'}`}>
          <Link to="/dashboard" className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary flex-shrink-0" />
            {!collapsed && <span className="font-bold text-lg">SecureScan</span>}
          </Link>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setCollapsed(!collapsed)}
            className="hidden lg:flex"
            data-testid="collapse-sidebar-btn"
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </Button>
        </div>

        {/* Navigation */}
        <ScrollArea className="flex-1 py-4">
          <nav className="space-y-1 px-2">
            {filteredNavItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.key}
                  to={item.path}
                  onClick={() => setMobileOpen(false)}
                  data-testid={`nav-${item.key}`}
                >
                  <Button
                    variant={isActive ? 'secondary' : 'ghost'}
                    className={cn(
                      'w-full justify-start gap-3',
                      collapsed && 'justify-center px-2',
                      isActive && 'bg-primary/10 text-primary border border-primary/20'
                    )}
                  >
                    <Icon className="h-5 w-5 flex-shrink-0" />
                    {!collapsed && <span>{t(item.key)}</span>}
                  </Button>
                </Link>
              );
            })}
          </nav>
        </ScrollArea>

        {/* User section */}
        <div className={`p-2 border-t ${theme === 'light' ? 'border-gray-200' : 'border-border'}`}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className={cn('w-full justify-start gap-3', collapsed && 'justify-center px-2')}
                data-testid="user-menu-btn"
              >
                <div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                  <User className="h-4 w-4 text-primary" />
                </div>
                {!collapsed && (
                  <div className="text-left overflow-hidden">
                    <p className="text-sm font-medium truncate">{user?.name}</p>
                    <p className={`text-xs truncate ${theme === 'light' ? 'text-gray-500' : 'text-muted-foreground'}`}>{user?.role}</p>
                  </div>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>{user?.email}</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={toggleTheme}>
                {theme === 'dark' ? <Sun className="mr-2 h-4 w-4" /> : <Moon className="mr-2 h-4 w-4" />}
                {theme === 'dark' ? (language === 'tr' ? 'Aydınlık Tema' : 'Light Theme') : (language === 'tr' ? 'Karanlık Tema' : 'Dark Theme')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => changeLanguage(language === 'tr' ? 'en' : 'tr')}>
                <Globe className="mr-2 h-4 w-4" />
                {language === 'tr' ? 'English' : 'Türkçe'}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout} className="text-destructive">
                <LogOut className="mr-2 h-4 w-4" />
                {t('logout')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar for mobile */}
        <header className={`lg:hidden h-16 border-b flex items-center justify-between px-4 ${theme === 'light' ? 'border-gray-200 bg-white' : 'border-border bg-card'}`}>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setMobileOpen(true)}
            data-testid="mobile-menu-btn"
          >
            <Menu className="h-5 w-5" />
          </Button>
          <Shield className="h-8 w-8 text-primary" />
          <Button variant="ghost" size="icon" onClick={toggleTheme}>
            {theme === 'dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
          </Button>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto">
          <div className="container mx-auto p-6 max-w-7xl fade-in">
            {children}
          </div>
        </main>

        {/* Footer */}
        <footer className={`py-4 px-6 text-center text-sm border-t ${theme === 'light' ? 'border-gray-200 text-gray-500' : 'border-border text-muted-foreground'}`}>
          © 2026 Tres Technology LLC. {language === 'tr' ? 'Tüm hakları saklıdır.' : 'All rights reserved.'}
        </footer>
      </div>
    </div>
  );
};

export default MainLayout;
