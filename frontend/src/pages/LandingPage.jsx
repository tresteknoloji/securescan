import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Button } from '../components/ui/button';
import { Card, CardContent } from '../components/ui/card';
import {
  Shield,
  Radar,
  FileText,
  Users,
  Globe,
  Lock,
  CheckCircle,
  ArrowRight,
  Server,
  AlertTriangle,
  BarChart3,
  Zap,
  Moon,
  Sun,
} from 'lucide-react';
import { useLanguage } from '../contexts/AppContext';

const features = [
  {
    icon: Radar,
    titleTr: 'Kapsamlı Port Tarama',
    titleEn: 'Comprehensive Port Scanning',
    descTr: 'Nmap entegrasyonu ile 65,535 porta kadar tam tarama desteği',
    descEn: 'Full scanning support up to 65,535 ports with Nmap integration',
  },
  {
    icon: Shield,
    titleTr: 'CVE Veritabanı',
    titleEn: 'CVE Database',
    descTr: 'NVD API ile güncel zafiyet veritabanı entegrasyonu',
    descEn: 'Up-to-date vulnerability database integration with NVD API',
  },
  {
    icon: Lock,
    titleTr: 'SSL/TLS Analizi',
    titleEn: 'SSL/TLS Analysis',
    descTr: 'Sertifika kontrolü, protokol versiyonu ve cipher suite analizi',
    descEn: 'Certificate check, protocol version and cipher suite analysis',
  },
  {
    icon: FileText,
    titleTr: 'Profesyonel Raporlama',
    titleEn: 'Professional Reporting',
    descTr: 'Özelleştirilebilir HTML ve PDF raporlar, PCI DSS uyumluluk',
    descEn: 'Customizable HTML and PDF reports, PCI DSS compliance',
  },
  {
    icon: Users,
    titleTr: 'Çoklu Kullanıcı Yönetimi',
    titleEn: 'Multi-User Management',
    descTr: 'Admin, Bayi ve Müşteri rolleri ile hiyerarşik yapı',
    descEn: 'Hierarchical structure with Admin, Reseller and Customer roles',
  },
  {
    icon: Globe,
    titleTr: 'Çoklu Dil Desteği',
    titleEn: 'Multi-Language Support',
    descTr: 'Türkçe ve İngilizce tam arayüz desteği',
    descEn: 'Full interface support in Turkish and English',
  },
];

const stats = [
  { value: '65K+', labelTr: 'Port Tarama', labelEn: 'Port Scanning' },
  { value: '200K+', labelTr: 'CVE Kaydı', labelEn: 'CVE Records' },
  { value: '99.9%', labelTr: 'Uptime', labelEn: 'Uptime' },
  { value: '24/7', labelTr: 'Destek', labelEn: 'Support' },
];

export default function LandingPage() {
  const { language, changeLanguage } = useLanguage();
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    localStorage.setItem('theme', newTheme);
    document.documentElement.classList.toggle('light', newTheme === 'light');
  };

  const isEn = language === 'en';

  return (
    <div className={`min-h-screen ${theme === 'light' ? 'bg-white text-gray-900' : 'bg-background text-foreground'}`} data-testid="landing-page">
      {/* Header */}
      <header className={`border-b ${theme === 'light' ? 'border-gray-200 bg-white' : 'border-border bg-card'}`}>
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold">SecureScan</span>
          </div>
          <div className="flex items-center gap-4">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => changeLanguage(isEn ? 'tr' : 'en')}
            >
              {isEn ? 'TR' : 'EN'}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={toggleTheme}
            >
              {theme === 'dark' ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </Button>
            <Link to="/login">
              <Button data-testid="login-btn">
                {isEn ? 'Login' : 'Giriş Yap'}
              </Button>
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 px-6">
        <div className="container mx-auto text-center max-w-4xl">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm mb-6">
            <Zap className="h-4 w-4" />
            {isEn ? 'Enterprise Security Solution' : 'Kurumsal Güvenlik Çözümü'}
          </div>
          <h1 className="text-4xl md:text-6xl font-bold mb-6 leading-tight">
            {isEn ? (
              <>Professional <span className="text-primary">Vulnerability</span> Scanner</>
            ) : (
              <>Profesyonel <span className="text-primary">Zafiyet</span> Tarama Platformu</>
            )}
          </h1>
          <p className={`text-lg md:text-xl mb-8 max-w-2xl mx-auto ${theme === 'light' ? 'text-gray-600' : 'text-muted-foreground'}`}>
            {isEn
              ? 'Protect your digital assets with comprehensive vulnerability scanning, real-time monitoring, and detailed compliance reporting.'
              : 'Kapsamlı zafiyet taraması, gerçek zamanlı izleme ve detaylı uyumluluk raporlaması ile dijital varlıklarınızı koruyun.'}
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link to="/login">
              <Button size="lg" className="gap-2" data-testid="hero-login-btn">
                {isEn ? 'Start Scanning' : 'Taramaya Başla'}
                <ArrowRight className="h-5 w-5" />
              </Button>
            </Link>
            <Button size="lg" variant="outline" className="gap-2">
              {isEn ? 'Learn More' : 'Daha Fazla Bilgi'}
            </Button>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className={`py-16 ${theme === 'light' ? 'bg-gray-50' : 'bg-secondary/30'}`}>
        <div className="container mx-auto px-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <div key={index} className="text-center">
                <div className="text-3xl md:text-4xl font-bold text-primary mb-2">{stat.value}</div>
                <div className={theme === 'light' ? 'text-gray-600' : 'text-muted-foreground'}>
                  {isEn ? stat.labelEn : stat.labelTr}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 px-6">
        <div className="container mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              {isEn ? 'Powerful Features' : 'Güçlü Özellikler'}
            </h2>
            <p className={`max-w-2xl mx-auto ${theme === 'light' ? 'text-gray-600' : 'text-muted-foreground'}`}>
              {isEn
                ? 'Everything you need for comprehensive security assessment'
                : 'Kapsamlı güvenlik değerlendirmesi için ihtiyacınız olan her şey'}
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <Card
                  key={index}
                  className={`card-hover ${theme === 'light' ? 'bg-white border-gray-200' : 'bg-card border-border'}`}
                >
                  <CardContent className="p-6">
                    <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                      <Icon className="h-6 w-6 text-primary" />
                    </div>
                    <h3 className="text-lg font-semibold mb-2">
                      {isEn ? feature.titleEn : feature.titleTr}
                    </h3>
                    <p className={theme === 'light' ? 'text-gray-600 text-sm' : 'text-muted-foreground text-sm'}>
                      {isEn ? feature.descEn : feature.descTr}
                    </p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      {/* Security Levels Section */}
      <section className={`py-20 px-6 ${theme === 'light' ? 'bg-gray-50' : 'bg-secondary/30'}`}>
        <div className="container mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              {isEn ? 'Severity Classification' : 'Zafiyet Derecelendirmesi'}
            </h2>
            <p className={`max-w-2xl mx-auto ${theme === 'light' ? 'text-gray-600' : 'text-muted-foreground'}`}>
              {isEn
                ? 'Industry-standard vulnerability classification for prioritized remediation'
                : 'Öncelikli iyileştirme için endüstri standardı zafiyet sınıflandırması'}
            </p>
          </div>
          <div className="flex flex-wrap justify-center gap-4">
            {[
              { label: 'Critical', labelTr: 'Kritik', color: 'bg-red-500' },
              { label: 'High', labelTr: 'Yüksek', color: 'bg-orange-500' },
              { label: 'Medium', labelTr: 'Orta', color: 'bg-yellow-500' },
              { label: 'Low', labelTr: 'Düşük', color: 'bg-yellow-400' },
              { label: 'Info', labelTr: 'Bilgi', color: 'bg-blue-500' },
            ].map((level, index) => (
              <div
                key={index}
                className={`flex items-center gap-3 px-6 py-3 rounded-lg ${theme === 'light' ? 'bg-white border border-gray-200' : 'bg-card border border-border'}`}
              >
                <div className={`w-4 h-4 rounded-full ${level.color}`} />
                <span className="font-medium">{isEn ? level.label : level.labelTr}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-6">
        <div className="container mx-auto text-center max-w-3xl">
          <AlertTriangle className="h-16 w-16 text-primary mx-auto mb-6" />
          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            {isEn ? 'Ready to Secure Your Infrastructure?' : 'Altyapınızı Güvence Altına Almaya Hazır mısınız?'}
          </h2>
          <p className={`mb-8 ${theme === 'light' ? 'text-gray-600' : 'text-muted-foreground'}`}>
            {isEn
              ? 'Start identifying vulnerabilities before attackers do.'
              : 'Saldırganlardan önce zafiyetleri tespit etmeye başlayın.'}
          </p>
          <Link to="/login">
            <Button size="lg" className="gap-2">
              {isEn ? 'Get Started Now' : 'Hemen Başlayın'}
              <ArrowRight className="h-5 w-5" />
            </Button>
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className={`py-12 px-6 border-t ${theme === 'light' ? 'border-gray-200 bg-gray-50' : 'border-border bg-card'}`}>
        <div className="container mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-3">
              <Shield className="h-6 w-6 text-primary" />
              <span className="font-semibold">SecureScan</span>
            </div>
            <div className={`text-sm ${theme === 'light' ? 'text-gray-600' : 'text-muted-foreground'}`}>
              © 2026 Tres Technology LLC. {isEn ? 'All rights reserved.' : 'Tüm hakları saklıdır.'}
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
