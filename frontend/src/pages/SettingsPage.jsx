import { useEffect, useState } from 'react';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Switch } from '../components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { Settings, Palette, Mail, Loader2, Save, Database, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';

export default function SettingsPage() {
  const { api } = useAuth();
  const { t } = useLanguage();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [cveStatus, setCveStatus] = useState(null);
  const [testEmail, setTestEmail] = useState('');
  
  const [branding, setBranding] = useState({
    company_name: '',
    logo_url: '',
    primary_color: '#3B82F6',
    secondary_color: '#1E293B',
    report_header_text: '',
    report_footer_text: '',
  });
  
  const [smtp, setSmtp] = useState({
    host: '',
    port: 587,
    username: '',
    password: '',
    use_tls: true,
    use_ssl: false,
    sender_name: '',
    sender_email: '',
  });

  useEffect(() => {
    fetchSettings();
    fetchCveStatus();
  }, []);

  const fetchSettings = async () => {
    try {
      const [brandingRes, smtpRes] = await Promise.all([
        api.get('/settings/branding'),
        api.get('/settings/smtp'),
      ]);
      
      if (brandingRes.data) {
        setBranding(brandingRes.data);
      }
      if (smtpRes.data) {
        setSmtp({ ...smtpRes.data, password: '' });
      }
    } catch (error) {
      console.error('Failed to fetch settings:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchCveStatus = async () => {
    try {
      const response = await api.get('/cve/status');
      setCveStatus(response.data);
    } catch (error) {
      console.error('Failed to fetch CVE status:', error);
    }
  };

  const saveBranding = async () => {
    setSaving(true);
    try {
      await api.post('/settings/branding', branding);
      toast.success(t('success'));
    } catch (error) {
      toast.error(error.response?.data?.detail || t('error'));
    } finally {
      setSaving(false);
    }
  };

  const saveSmtp = async () => {
    setSaving(true);
    try {
      await api.post('/settings/smtp', smtp);
      toast.success(t('success'));
    } catch (error) {
      toast.error(error.response?.data?.detail || t('error'));
    } finally {
      setSaving(false);
    }
  };

  const testSmtp = async () => {
    if (!testEmail) {
      toast.error('Please enter a test email address');
      return;
    }
    setTesting(true);
    try {
      await api.post(`/settings/smtp/test?test_email=${encodeURIComponent(testEmail)}`);
      toast.success(`Test email sent to ${testEmail}`);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to send test email');
    } finally {
      setTesting(false);
    }
  };

  const syncCve = async () => {
    setSyncing(true);
    try {
      await api.post('/cve/sync');
      toast.success('CVE sync started');
      // Refresh status after a delay
      setTimeout(fetchCveStatus, 5000);
    } catch (error) {
      toast.error(error.response?.data?.detail || t('error'));
    } finally {
      setSyncing(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96" data-testid="settings-loading">
        <Loader2 className="h-8 w-8 spinner text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="settings-page">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">{t('settings')}</h1>
        <p className="text-muted-foreground">Configure branding, email, and system settings</p>
      </div>

      <Tabs defaultValue="branding" className="space-y-6">
        <TabsList>
          <TabsTrigger value="branding" className="gap-2">
            <Palette className="h-4 w-4" />
            {t('branding')}
          </TabsTrigger>
          <TabsTrigger value="smtp" className="gap-2">
            <Mail className="h-4 w-4" />
            {t('smtp_settings')}
          </TabsTrigger>
        </TabsList>

        {/* Branding Tab */}
        <TabsContent value="branding">
          <Card data-testid="branding-card">
            <CardHeader>
              <CardTitle>{t('branding')}</CardTitle>
              <CardDescription>
                Customize the look of reports and dashboard
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label htmlFor="company_name">{t('company_name')}</Label>
                  <Input
                    id="company_name"
                    value={branding.company_name}
                    onChange={(e) => setBranding({ ...branding, company_name: e.target.value })}
                    placeholder="Your Company Name"
                    data-testid="company-name-input"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="logo_url">{t('logo_url')}</Label>
                  <Input
                    id="logo_url"
                    value={branding.logo_url || ''}
                    onChange={(e) => setBranding({ ...branding, logo_url: e.target.value })}
                    placeholder="https://example.com/logo.png"
                    data-testid="logo-url-input"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="primary_color">{t('primary_color')}</Label>
                  <div className="flex gap-2">
                    <Input
                      id="primary_color"
                      type="color"
                      value={branding.primary_color}
                      onChange={(e) => setBranding({ ...branding, primary_color: e.target.value })}
                      className="w-16 h-10 p-1"
                      data-testid="primary-color-input"
                    />
                    <Input
                      value={branding.primary_color}
                      onChange={(e) => setBranding({ ...branding, primary_color: e.target.value })}
                      placeholder="#3B82F6"
                      className="mono flex-1"
                    />
                  </div>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="secondary_color">{t('secondary_color')}</Label>
                  <div className="flex gap-2">
                    <Input
                      id="secondary_color"
                      type="color"
                      value={branding.secondary_color}
                      onChange={(e) => setBranding({ ...branding, secondary_color: e.target.value })}
                      className="w-16 h-10 p-1"
                      data-testid="secondary-color-input"
                    />
                    <Input
                      value={branding.secondary_color}
                      onChange={(e) => setBranding({ ...branding, secondary_color: e.target.value })}
                      placeholder="#1E293B"
                      className="mono flex-1"
                    />
                  </div>
                </div>
                
                <div className="space-y-2 md:col-span-2">
                  <Label htmlFor="report_header">{t('report_header')}</Label>
                  <Input
                    id="report_header"
                    value={branding.report_header_text || ''}
                    onChange={(e) => setBranding({ ...branding, report_header_text: e.target.value })}
                    placeholder="Confidential Security Report"
                    data-testid="report-header-input"
                  />
                </div>
                
                <div className="space-y-2 md:col-span-2">
                  <Label htmlFor="report_footer">{t('report_footer')}</Label>
                  <Input
                    id="report_footer"
                    value={branding.report_footer_text || ''}
                    onChange={(e) => setBranding({ ...branding, report_footer_text: e.target.value })}
                    placeholder="© 2024 Your Company. All rights reserved."
                    data-testid="report-footer-input"
                  />
                </div>
              </div>
              
              <Button onClick={saveBranding} disabled={saving} data-testid="save-branding-btn">
                {saving ? (
                  <Loader2 className="mr-2 h-4 w-4 spinner" />
                ) : (
                  <Save className="mr-2 h-4 w-4" />
                )}
                {t('save')}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* SMTP Tab */}
        <TabsContent value="smtp">
          <Card data-testid="smtp-card">
            <CardHeader>
              <CardTitle>{t('smtp_settings')}</CardTitle>
              <CardDescription>
                Configure email settings for notifications
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label htmlFor="smtp_host">{t('smtp_host')}</Label>
                  <Input
                    id="smtp_host"
                    value={smtp.host}
                    onChange={(e) => setSmtp({ ...smtp, host: e.target.value })}
                    placeholder="smtp.example.com"
                    data-testid="smtp-host-input"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="smtp_port">{t('smtp_port')}</Label>
                  <Input
                    id="smtp_port"
                    type="number"
                    value={smtp.port}
                    onChange={(e) => setSmtp({ ...smtp, port: parseInt(e.target.value) })}
                    placeholder="587"
                    data-testid="smtp-port-input"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="smtp_user">{t('smtp_user')}</Label>
                  <Input
                    id="smtp_user"
                    value={smtp.username}
                    onChange={(e) => setSmtp({ ...smtp, username: e.target.value })}
                    placeholder="user@example.com"
                    data-testid="smtp-user-input"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="smtp_pass">{t('smtp_pass')}</Label>
                  <Input
                    id="smtp_pass"
                    type="password"
                    value={smtp.password}
                    onChange={(e) => setSmtp({ ...smtp, password: e.target.value })}
                    placeholder="••••••••"
                    data-testid="smtp-pass-input"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="sender_name">{t('sender_name')}</Label>
                  <Input
                    id="sender_name"
                    value={smtp.sender_name}
                    onChange={(e) => setSmtp({ ...smtp, sender_name: e.target.value })}
                    placeholder="Security Scanner"
                    data-testid="sender-name-input"
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="sender_email">{t('sender_email')}</Label>
                  <Input
                    id="sender_email"
                    type="email"
                    value={smtp.sender_email}
                    onChange={(e) => setSmtp({ ...smtp, sender_email: e.target.value })}
                    placeholder="noreply@example.com"
                    data-testid="sender-email-input"
                  />
                </div>
                
                <div className="flex items-center gap-4 md:col-span-2">
                  <div className="flex items-center gap-2">
                    <Switch
                      id="use_tls"
                      checked={smtp.use_tls}
                      onCheckedChange={(v) => setSmtp({ ...smtp, use_tls: v, use_ssl: v ? false : smtp.use_ssl })}
                      data-testid="use-tls-switch"
                    />
                    <Label htmlFor="use_tls">{t('use_tls')}</Label>
                  </div>
                  
                  <div className="flex items-center gap-2">
                    <Switch
                      id="use_ssl"
                      checked={smtp.use_ssl}
                      onCheckedChange={(v) => setSmtp({ ...smtp, use_ssl: v, use_tls: v ? false : smtp.use_tls })}
                      data-testid="use-ssl-switch"
                    />
                    <Label htmlFor="use_ssl">{t('use_ssl')}</Label>
                  </div>
                </div>
              </div>
              
              <div className="flex flex-wrap gap-4">
                <Button onClick={saveSmtp} disabled={saving} data-testid="save-smtp-btn">
                  {saving ? (
                    <Loader2 className="mr-2 h-4 w-4 spinner" />
                  ) : (
                    <Save className="mr-2 h-4 w-4" />
                  )}
                  {t('save')}
                </Button>
                
                <div className="flex gap-2 flex-1 max-w-md">
                  <Input
                    placeholder="test@example.com"
                    value={testEmail}
                    onChange={(e) => setTestEmail(e.target.value)}
                    data-testid="test-email-input"
                  />
                  <Button 
                    variant="outline" 
                    onClick={testSmtp} 
                    disabled={testing || !smtp.host}
                    data-testid="test-smtp-btn"
                  >
                    {testing ? (
                      <Loader2 className="mr-2 h-4 w-4 spinner" />
                    ) : (
                      <Mail className="mr-2 h-4 w-4" />
                    )}
                    Test
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* CVE Database Tab */}
        <TabsContent value="cve">
          <Card data-testid="cve-card">
            <CardHeader>
              <CardTitle>CVE Database</CardTitle>
              <CardDescription>
                Manage vulnerability database from NVD
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="p-4 bg-secondary/30 rounded-sm">
                  <p className="text-sm text-muted-foreground mb-1">Total CVEs</p>
                  <p className="text-2xl font-bold mono">{cveStatus?.total_cves || 0}</p>
                </div>
                
                <div className="p-4 bg-secondary/30 rounded-sm">
                  <p className="text-sm text-muted-foreground mb-1">Last Sync</p>
                  <p className="text-lg font-medium mono">
                    {cveStatus?.last_sync
                      ? new Date(cveStatus.last_sync).toLocaleString()
                      : 'Never'}
                  </p>
                </div>
              </div>
              
              <Button onClick={syncCve} disabled={syncing} data-testid="sync-cve-btn">
                {syncing ? (
                  <Loader2 className="mr-2 h-4 w-4 spinner" />
                ) : (
                  <RefreshCw className="mr-2 h-4 w-4" />
                )}
                Sync CVE Database
              </Button>
              
              <p className="text-sm text-muted-foreground">
                CVE data is synced from the National Vulnerability Database (NVD). 
                Syncing fetches CVEs from the last 30 days.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
