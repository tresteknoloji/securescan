import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../contexts/AppContext';
import { useLanguage } from '../contexts/AppContext';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Shield, Eye, EyeOff, Loader2, ArrowLeft, Moon, Sun } from 'lucide-react';
import { toast } from 'sonner';

export default function LoginPage() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const { t, language, changeLanguage } = useLanguage();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');

  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
  }, [theme]);

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    localStorage.setItem('theme', newTheme);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await login(email, password);
      toast.success(t('success'));
      navigate('/dashboard');
    } catch (error) {
      toast.error(error.response?.data?.detail || t('error'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`min-h-screen flex ${theme === 'light' ? 'bg-gray-50' : 'bg-background'}`} data-testid="login-page">
      {/* Left side - Image */}
      <div 
        className="hidden lg:flex lg:w-1/2 relative bg-cover bg-center"
        style={{ 
          backgroundImage: 'url(https://images.unsplash.com/photo-1680992046626-418f7e910589?crop=entropy&cs=srgb&fm=jpg&q=85)',
        }}
      >
        <div className={`absolute inset-0 ${theme === 'light' ? 'bg-white/80' : 'bg-background/90'}`} />
        <div className="relative z-10 flex flex-col justify-center p-12">
          <div className="flex items-center gap-3 mb-6">
            <Shield className="h-12 w-12 text-primary" />
            <h1 className="text-4xl font-bold">SecureScan</h1>
          </div>
          <p className={`text-xl max-w-md ${theme === 'light' ? 'text-gray-600' : 'text-muted-foreground'}`}>
            {language === 'tr' 
              ? 'Kurumsal güvenlik için profesyonel zafiyet tarama platformu'
              : 'Professional vulnerability scanning platform for enterprise security'}
          </p>
        </div>
      </div>

      {/* Right side - Form */}
      <div className={`flex-1 flex flex-col ${theme === 'light' ? 'bg-white' : 'bg-background'}`}>
        {/* Top Bar */}
        <div className="flex items-center justify-between p-4">
          <Link to="/">
            <Button variant="ghost" size="sm" className="gap-2">
              <ArrowLeft className="h-4 w-4" />
              {language === 'tr' ? 'Ana Sayfa' : 'Home'}
            </Button>
          </Link>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => changeLanguage(language === 'tr' ? 'en' : 'tr')}
            >
              {language === 'tr' ? 'EN' : 'TR'}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={toggleTheme}
            >
              {theme === 'dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </Button>
          </div>
        </div>

        {/* Form Container */}
        <div className="flex-1 flex items-center justify-center p-8">
          <Card className={`w-full max-w-md ${theme === 'light' ? 'bg-white border-gray-200' : 'border-border bg-card'}`}>
            <CardHeader className="space-y-1 text-center">
              <div className="lg:hidden flex justify-center mb-4">
                <Shield className="h-10 w-10 text-primary" />
              </div>
              <CardTitle className="text-2xl font-bold">{t('welcome_back')}</CardTitle>
              <CardDescription>{t('sign_in_to_continue')}</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">{t('email')}</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="admin@securescan.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    data-testid="login-email-input"
                    className={theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-secondary/50'}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">{t('password')}</Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      data-testid="login-password-input"
                      className={`pr-10 ${theme === 'light' ? 'bg-gray-50 border-gray-200' : 'bg-secondary/50'}`}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
                <Button
                  type="submit"
                  className="w-full"
                  disabled={loading}
                  data-testid="login-submit-btn"
                >
                  {loading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 spinner" />
                      {t('loading')}
                    </>
                  ) : (
                    t('login')
                  )}
                </Button>
              </form>
              <div className={`mt-6 p-3 rounded-sm text-sm ${theme === 'light' ? 'bg-gray-100' : 'bg-secondary/30'}`}>
                <p className={theme === 'light' ? 'text-gray-600' : 'text-muted-foreground'}>
                  Demo: admin@securescan.com / admin123
                </p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Footer */}
        <div className={`p-4 text-center text-sm ${theme === 'light' ? 'text-gray-500' : 'text-muted-foreground'}`}>
          © 2026 Tres Technology LLC. {language === 'tr' ? 'Tüm hakları saklıdır.' : 'All rights reserved.'}
        </div>
      </div>
    </div>
  );
}
