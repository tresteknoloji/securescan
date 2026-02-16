import { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import axios from 'axios';

const API_URL = `${process.env.REACT_APP_BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  // Create api instance with useMemo to prevent recreation
  const api = useMemo(() => {
    const instance = axios.create({
      baseURL: API_URL,
    });
    
    // Add token interceptor
    instance.interceptors.request.use((config) => {
      const currentToken = localStorage.getItem('token');
      if (currentToken) {
        config.headers.Authorization = `Bearer ${currentToken}`;
      }
      return config;
    });
    
    return instance;
  }, []);

  const fetchUser = useCallback(async () => {
    const currentToken = localStorage.getItem('token');
    if (!currentToken) {
      setLoading(false);
      return;
    }

    try {
      const response = await api.get('/auth/me');
      setUser(response.data);
    } catch (error) {
      console.error('Failed to fetch user:', error);
      localStorage.removeItem('token');
      setToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const login = useCallback(async (email, password) => {
    const response = await api.post('/auth/login', { email, password });
    const { access_token, user: userData } = response.data;
    localStorage.setItem('token', access_token);
    setToken(access_token);
    setUser(userData);
    return userData;
  }, [api]);

  const register = useCallback(async (data) => {
    const response = await api.post('/auth/register', data);
    const { access_token, user: userData } = response.data;
    localStorage.setItem('token', access_token);
    setToken(access_token);
    setUser(userData);
    return userData;
  }, [api]);

  const logout = useCallback(() => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  }, []);

  const updateUser = useCallback((userData) => {
    setUser(userData);
  }, []);

  const contextValue = useMemo(() => ({
    user,
    token,
    loading,
    login,
    register,
    logout,
    updateUser,
    api,
    isAdmin: user?.role === 'admin',
    isReseller: user?.role === 'reseller',
    isCustomer: user?.role === 'customer',
  }), [user, token, loading, api, login, register, logout, updateUser]);

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};

// Language Context
const LanguageContext = createContext(null);

export const useLanguage = () => {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within LanguageProvider');
  }
  return context;
};

const defaultTranslations = {
  tr: {
    dashboard: "Kontrol Paneli",
    targets: "Hedefler",
    scans: "Taramalar",
    reports: "Raporlar",
    users: "Kullanıcılar",
    settings: "Ayarlar",
    login: "Giriş Yap",
    logout: "Çıkış Yap",
    new_scan: "Yeni Tarama",
    add_target: "Hedef Ekle",
    critical: "Kritik",
    high: "Yüksek",
    medium: "Orta",
    low: "Düşük",
    info: "Bilgi",
    pending: "Bekliyor",
    running: "Çalışıyor",
    completed: "Tamamlandı",
    failed: "Başarısız",
    cancelled: "İptal Edildi",
    ip_address: "IP Adresi",
    domain: "Alan Adı",
    prefix: "Alt Ağ (Prefix)",
    vulnerabilities: "Zafiyetler",
    total: "Toplam",
    scan_name: "Tarama Adı",
    target_name: "Hedef Adı",
    start_scan: "Taramayı Başlat",
    stop_scan: "Taramayı Durdur",
    download_report: "Raporu İndir",
    branding: "Marka Ayarları",
    smtp_settings: "E-posta Ayarları",
    profile: "Profil",
    customers: "Müşteriler",
    resellers: "Bayiler",
    monthly_limit: "Aylık Limit",
    targets_limit: "Hedef Limiti",
    customers_limit: "Müşteri Limiti",
    unlimited: "Limitsiz",
    used: "Kullanılan",
    remaining: "Kalan",
    email: "E-posta",
    password: "Şifre",
    name: "İsim",
    save: "Kaydet",
    cancel: "İptal",
    delete: "Sil",
    edit: "Düzenle",
    actions: "İşlemler",
    status: "Durum",
    created: "Oluşturulma",
    progress: "İlerleme",
    details: "Detaylar",
    value: "Değer",
    type: "Tür",
    description: "Açıklama",
    no_data: "Veri bulunamadı",
    loading: "Yükleniyor...",
    error: "Hata",
    success: "Başarılı",
    confirm_delete: "Silmek istediğinize emin misiniz?",
    select_targets: "Hedef Seçin",
    scan_config: "Tarama Ayarları",
    port_range: "Port Aralığı",
    all_ports: "Tüm Portlar (1-65535)",
    quick_scan: "Hızlı Tarama (Top 100)",
    full_scan: "Tam Tarama",
    stealth_scan: "Gizli Tarama",
    check_ssl: "SSL/TLS Kontrolü",
    check_cve: "CVE Kontrolü",
    pci_compliance: "PCI Uyumluluk",
    recent_scans: "Son Taramalar",
    vulnerability_trend: "Zafiyet Trendi",
    total_scans: "Toplam Tarama",
    running_scans: "Aktif Tarama",
    total_targets: "Toplam Hedef",
    total_vulnerabilities: "Toplam Zafiyet",
    company_name: "Şirket Adı",
    logo_url: "Logo URL",
    primary_color: "Ana Renk",
    secondary_color: "İkincil Renk",
    report_header: "Rapor Başlığı",
    report_footer: "Rapor Altlığı",
    smtp_host: "SMTP Sunucu",
    smtp_port: "SMTP Port",
    smtp_user: "Kullanıcı Adı",
    smtp_pass: "Şifre",
    sender_name: "Gönderen Adı",
    sender_email: "Gönderen E-posta",
    use_tls: "TLS Kullan",
    use_ssl: "SSL Kullan",
    role: "Rol",
    admin: "Admin",
    reseller: "Bayi",
    customer: "Müşteri",
    live_results: "Canlı Sonuçlar",
    port: "Port",
    service: "Servis",
    solution: "Çözüm",
    cve: "CVE",
    references: "Referanslar",
    cve_database: "CVE Veritabanı",
    welcome_back: "Tekrar Hoş Geldiniz",
    sign_in_to_continue: "Devam etmek için giriş yapın",
    dont_have_account: "Hesabınız yok mu?",
    register_here: "Kayıt olun",
    already_have_account: "Zaten hesabınız var mı?",
    login_here: "Giriş yapın",
    create_account: "Hesap Oluştur",
    join_platform: "Platformumuza katılın",
  },
  en: {
    dashboard: "Dashboard",
    targets: "Targets",
    scans: "Scans",
    reports: "Reports",
    users: "Users",
    settings: "Settings",
    login: "Login",
    logout: "Logout",
    new_scan: "New Scan",
    add_target: "Add Target",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
    pending: "Pending",
    running: "Running",
    completed: "Completed",
    failed: "Failed",
    cancelled: "Cancelled",
    ip_address: "IP Address",
    domain: "Domain",
    prefix: "Subnet (Prefix)",
    vulnerabilities: "Vulnerabilities",
    total: "Total",
    scan_name: "Scan Name",
    target_name: "Target Name",
    start_scan: "Start Scan",
    stop_scan: "Stop Scan",
    download_report: "Download Report",
    branding: "Branding",
    smtp_settings: "Email Settings",
    profile: "Profile",
    customers: "Customers",
    resellers: "Resellers",
    monthly_limit: "Monthly Limit",
    targets_limit: "Targets Limit",
    customers_limit: "Customers Limit",
    unlimited: "Unlimited",
    used: "Used",
    remaining: "Remaining",
    email: "Email",
    password: "Password",
    name: "Name",
    save: "Save",
    cancel: "Cancel",
    delete: "Delete",
    edit: "Edit",
    actions: "Actions",
    status: "Status",
    created: "Created",
    progress: "Progress",
    details: "Details",
    value: "Value",
    type: "Type",
    description: "Description",
    no_data: "No data found",
    loading: "Loading...",
    error: "Error",
    success: "Success",
    confirm_delete: "Are you sure you want to delete?",
    select_targets: "Select Targets",
    scan_config: "Scan Configuration",
    port_range: "Port Range",
    all_ports: "All Ports (1-65535)",
    quick_scan: "Quick Scan (Top 100)",
    full_scan: "Full Scan",
    stealth_scan: "Stealth Scan",
    check_ssl: "SSL/TLS Check",
    check_cve: "CVE Check",
    pci_compliance: "PCI Compliance",
    recent_scans: "Recent Scans",
    vulnerability_trend: "Vulnerability Trend",
    total_scans: "Total Scans",
    running_scans: "Running Scans",
    total_targets: "Total Targets",
    total_vulnerabilities: "Total Vulnerabilities",
    company_name: "Company Name",
    logo_url: "Logo URL",
    primary_color: "Primary Color",
    secondary_color: "Secondary Color",
    report_header: "Report Header",
    report_footer: "Report Footer",
    smtp_host: "SMTP Host",
    smtp_port: "SMTP Port",
    smtp_user: "Username",
    smtp_pass: "Password",
    sender_name: "Sender Name",
    sender_email: "Sender Email",
    use_tls: "Use TLS",
    use_ssl: "Use SSL",
    role: "Role",
    admin: "Admin",
    reseller: "Reseller",
    customer: "Customer",
    live_results: "Live Results",
    port: "Port",
    service: "Service",
    solution: "Solution",
    cve: "CVE",
    references: "References",
    cve_database: "CVE Database",
    welcome_back: "Welcome Back",
    sign_in_to_continue: "Sign in to continue",
    dont_have_account: "Don't have an account?",
    register_here: "Register here",
    already_have_account: "Already have an account?",
    login_here: "Login here",
    create_account: "Create Account",
    join_platform: "Join our platform",
  }
};

export const LanguageProvider = ({ children }) => {
  const [language, setLanguage] = useState(localStorage.getItem('language') || 'tr');
  
  const translations = useMemo(() => {
    return defaultTranslations[language] || defaultTranslations.en;
  }, [language]);

  useEffect(() => {
    localStorage.setItem('language', language);
  }, [language]);

  const t = useCallback((key) => {
    return translations[key] || key;
  }, [translations]);

  const changeLanguage = useCallback((lang) => {
    setLanguage(lang);
  }, []);

  const value = useMemo(() => ({
    language,
    t,
    changeLanguage
  }), [language, t, changeLanguage]);

  return (
    <LanguageContext.Provider value={value}>
      {children}
    </LanguageContext.Provider>
  );
};

export default AuthContext;
