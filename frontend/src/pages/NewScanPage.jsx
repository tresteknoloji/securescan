import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Checkbox } from '../components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select';
import { Badge } from '../components/ui/badge';
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '../components/ui/alert';
import {
  Radar,
  Target,
  Settings,
  Play,
  Globe,
  Server,
  Network,
  Loader2,
  ArrowLeft,
  Shield,
  Lock,
  Search,
  HardDrive,
  AlertTriangle,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { toast } from 'sonner';

const TYPE_ICONS = {
  ip: Server,
  domain: Globe,
  prefix: Network,
};

export default function NewScanPage() {
  const navigate = useNavigate();
  const { api } = useAuth();
  const { t, language } = useLanguage();
  const [targets, setTargets] = useState([]);
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [selectedTargets, setSelectedTargets] = useState([]);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [scanName, setScanName] = useState('');
  const [config, setConfig] = useState({
    scan_type: 'quick',
    port_range: '1-1000',
    check_ssl: true,
    check_cve: true,
    pci_compliance: true,
    active_checks: true,
    exposure_level: 'internet',
    data_sensitivity: 'normal',
  });

  useEffect(() => {
    fetchData();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchData = async () => {
    try {
      const [targetsRes, agentsRes] = await Promise.all([
        api.get('/targets'),
        api.get('/agents')
      ]);
      setTargets(targetsRes.data.filter(t => t.is_active !== false));
      setAgents(agentsRes.data);
      
      // Auto-select first online agent if available
      const onlineAgents = agentsRes.data.filter(a => a.status === 'online');
      if (onlineAgents.length > 0) {
        setSelectedAgent(onlineAgents[0].id);
      }
    } catch (error) {
      toast.error('Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleTargetToggle = (targetId) => {
    setSelectedTargets((prev) =>
      prev.includes(targetId)
        ? prev.filter((id) => id !== targetId)
        : [...prev, targetId]
    );
  };

  const handleSelectAll = () => {
    if (selectedTargets.length === targets.length) {
      setSelectedTargets([]);
    } else {
      setSelectedTargets(targets.map(t => t.id));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (selectedTargets.length === 0) {
      toast.error(language === 'tr' ? 'En az bir hedef seçin' : 'Please select at least one target');
      return;
    }

    if (!scanName.trim()) {
      toast.error(language === 'tr' ? 'Tarama adı girin' : 'Please enter a scan name');
      return;
    }

    if (!selectedAgent) {
      toast.error(language === 'tr' ? 'Bir agent seçin' : 'Please select an agent');
      return;
    }

    // Check if selected agent is online
    const agent = agents.find(a => a.id === selectedAgent);
    if (agent && agent.status !== 'online') {
      toast.error(language === 'tr' ? 'Seçilen agent çevrimdışı' : 'Selected agent is offline');
      return;
    }

    // DNS Recursive scan only works with IP and Prefix targets
    if (config.scan_type === 'dns_recursive') {
      const selectedTargetObjects = targets.filter(t => selectedTargets.includes(t.id));
      const invalidTargets = selectedTargetObjects.filter(t => t.target_type === 'domain');
      if (invalidTargets.length > 0) {
        toast.error(
          language === 'tr' 
            ? 'Recursive DNS taraması sadece IP ve Prefix hedeflerle çalışır. Domain hedefleri kaldırın.' 
            : 'Recursive DNS scan only works with IP and Prefix targets. Remove domain targets.'
        );
        return;
      }
    }

    setSubmitting(true);

    try {
      // Determine port range based on scan type
      let portRange = config.port_range;
      if (config.scan_type === 'quick') portRange = '1-100';
      else if (config.scan_type === 'full') portRange = '1-65535';
      else if (config.scan_type === 'port_only') portRange = '1-65535';
      else if (config.scan_type === 'dns_recursive') portRange = '53';

      const response = await api.post('/scans', {
        name: scanName,
        target_ids: selectedTargets,
        agent_id: selectedAgent,
        config: {
          scan_type: config.scan_type,
          port_range: portRange,
          check_ssl: config.scan_type === 'dns_recursive' ? false : config.check_ssl,
          check_cve: config.scan_type === 'dns_recursive' ? false : config.check_cve,
          pci_compliance: config.scan_type === 'dns_recursive' ? false : config.pci_compliance,
        },
      });

      toast.success(language === 'tr' ? 'Tarama başlatıldı' : 'Scan started successfully');
      navigate(`/scans/${response.data.id}`);
    } catch (error) {
      toast.error(error.response?.data?.detail || t('error'));
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96" data-testid="new-scan-loading">
        <Loader2 className="h-8 w-8 spinner text-primary" />
      </div>
    );
  }

  // Check if user has any agents
  const hasAgents = agents.length > 0;
  const onlineAgents = agents.filter(a => a.status === 'online');
  const hasOnlineAgent = onlineAgents.length > 0;

  return (
    <div className="space-y-6" data-testid="new-scan-page">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => navigate('/scans')}
          data-testid="back-btn"
        >
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div>
          <h1 className="text-3xl font-bold">{t('new_scan')}</h1>
          <p className="text-muted-foreground">
            {language === 'tr' ? 'Yeni bir zafiyet taraması yapılandırın ve başlatın' : 'Configure and start a new vulnerability scan'}
          </p>
        </div>
      </div>

      {/* No Agent Warning */}
      {!hasAgents && (
        <Alert variant="destructive" data-testid="no-agent-warning">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>{language === 'tr' ? 'Agent Gerekli' : 'Agent Required'}</AlertTitle>
          <AlertDescription className="mt-2">
            {language === 'tr' 
              ? 'Tarama yapabilmek için önce bir agent eklemeniz gerekiyor. Agent, uzak sunucunuzda çalışarak tarama işlemlerini gerçekleştirir.'
              : 'You need to add an agent before you can start a scan. The agent runs on your remote server to perform the scanning operations.'}
            <Button
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={() => navigate('/agents')}
            >
              <HardDrive className="w-4 h-4 mr-2" />
              {language === 'tr' ? 'Agent Ekle' : 'Add Agent'}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* No Online Agent Warning */}
      {hasAgents && !hasOnlineAgent && (
        <Alert variant="destructive" data-testid="no-online-agent-warning">
          <WifiOff className="h-4 w-4" />
          <AlertTitle>{language === 'tr' ? 'Çevrimiçi Agent Yok' : 'No Online Agent'}</AlertTitle>
          <AlertDescription>
            {language === 'tr' 
              ? 'Tarama başlatmak için en az bir agent\'ın çevrimiçi olması gerekiyor. Agent\'larınızın durumunu kontrol edin.'
              : 'At least one agent must be online to start a scan. Check your agents status.'}
            <Button
              variant="outline"
              size="sm"
              className="mt-3"
              onClick={() => navigate('/agents')}
            >
              <HardDrive className="w-4 h-4 mr-2" />
              {language === 'tr' ? 'Agent\'ları Görüntüle' : 'View Agents'}
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Agent Selection - Full Width */}
          <Card className="lg:col-span-3" data-testid="agent-selection-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <HardDrive className="h-5 w-5" />
                {language === 'tr' ? 'Agent Seçimi' : 'Select Agent'}
              </CardTitle>
              <CardDescription>
                {language === 'tr' 
                  ? 'Taramayı gerçekleştirecek agent\'ı seçin'
                  : 'Select the agent that will perform the scan'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {agents.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {agents.map((agent) => {
                    const isOnline = agent.status === 'online';
                    const isSelected = selectedAgent === agent.id;
                    return (
                      <div
                        key={agent.id}
                        onClick={() => isOnline && setSelectedAgent(agent.id)}
                        className={`p-4 rounded-lg border-2 transition-all ${
                          isSelected
                            ? 'border-primary bg-primary/10'
                            : isOnline
                              ? 'border-border hover:border-primary/50 cursor-pointer'
                              : 'border-border/50 opacity-50 cursor-not-allowed'
                        }`}
                        data-testid={`agent-option-${agent.id}`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Server className="w-4 h-4 text-primary" />
                            <span className="font-medium">{agent.name}</span>
                          </div>
                          {isOnline ? (
                            <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                              <Wifi className="w-3 h-3 mr-1" />
                              {language === 'tr' ? 'Çevrimiçi' : 'Online'}
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-muted-foreground">
                              <WifiOff className="w-3 h-3 mr-1" />
                              {language === 'tr' ? 'Çevrimdışı' : 'Offline'}
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground font-mono">
                          {agent.ip_address || '-'}
                        </p>
                        {agent.os_info && (
                          <p className="text-xs text-muted-foreground mt-1">
                            {agent.os_info}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <HardDrive className="h-12 w-12 mx-auto mb-4 opacity-30" />
                  <p>{language === 'tr' ? 'Henüz agent eklenmemiş' : 'No agents available'}</p>
                  <Button
                    type="button"
                    variant="outline"
                    className="mt-4"
                    onClick={() => navigate('/agents')}
                  >
                    {language === 'tr' ? 'Agent Ekle' : 'Add Agent'}
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Scan Name */}
          <Card className="lg:col-span-3" data-testid="scan-name-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Radar className="h-5 w-5" />
                {t('scan_name')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Input
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                placeholder={language === 'tr' ? 'Tarama adı girin...' : 'Enter scan name...'}
                required
                disabled={!hasOnlineAgent}
                data-testid="scan-name-input"
                className="max-w-md"
              />
            </CardContent>
          </Card>

          {/* Target Selection */}
          <Card className="lg:col-span-2" data-testid="target-selection-card">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Target className="h-5 w-5" />
                    {t('select_targets')}
                  </CardTitle>
                  <CardDescription>
                    {selectedTargets.length} of {targets.length} selected
                  </CardDescription>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleSelectAll}
                  data-testid="select-all-btn"
                >
                  {selectedTargets.length === targets.length ? 'Deselect All' : 'Select All'}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {targets.length > 0 ? (
                <div className="h-80 overflow-y-auto">
                  <div className="space-y-2 pr-2">
                    {targets.map((target) => {
                      const TypeIcon = TYPE_ICONS[target.target_type] || Server;
                      const isSelected = selectedTargets.includes(target.id);
                      return (
                        <div
                          key={target.id}
                          onClick={() => handleTargetToggle(target.id)}
                          className={`flex items-center gap-3 p-3 rounded-sm border cursor-pointer transition-colors ${
                            isSelected
                              ? 'border-primary bg-primary/10'
                              : 'border-border hover:border-primary/50'
                          }`}
                          data-testid={`target-option-${target.id}`}
                        >
                          <div 
                            className="flex items-center justify-center w-4 h-4 border rounded-sm"
                            style={{
                              backgroundColor: isSelected ? 'hsl(var(--primary))' : 'transparent',
                              borderColor: isSelected ? 'hsl(var(--primary))' : 'hsl(var(--border))'
                            }}
                          >
                            {isSelected && (
                              <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                              </svg>
                            )}
                          </div>
                          <TypeIcon className="h-4 w-4 text-muted-foreground" />
                          <div className="flex-1 min-w-0">
                            <p className="font-medium truncate">{target.name}</p>
                            <p className="text-sm text-muted-foreground mono truncate">
                              {target.value}
                            </p>
                          </div>
                          <Badge variant="outline" className="text-xs">
                            {target.target_type}
                          </Badge>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Target className="h-12 w-12 mx-auto mb-4 opacity-30" />
                  <p>No targets available</p>
                  <Button
                    type="button"
                    variant="outline"
                    className="mt-4"
                    onClick={() => navigate('/targets')}
                  >
                    Add Targets
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Scan Configuration */}
          <Card data-testid="scan-config-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                {t('scan_config')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Scan Type */}
              <div className="space-y-2">
                <Label>{language === 'tr' ? 'Tarama Tipi' : 'Scan Type'}</Label>
                <Select
                  value={config.scan_type}
                  onValueChange={(v) => setConfig({ ...config, scan_type: v })}
                >
                  <SelectTrigger data-testid="scan-type-select">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">
                      <div className="flex items-center gap-2">
                        <Search className="h-4 w-4" />
                        {t('quick_scan')}
                      </div>
                    </SelectItem>
                    <SelectItem value="full">
                      <div className="flex items-center gap-2">
                        <Radar className="h-4 w-4" />
                        {t('full_scan')}
                      </div>
                    </SelectItem>
                    <SelectItem value="stealth">
                      <div className="flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        {t('stealth_scan')}
                      </div>
                    </SelectItem>
                    <SelectItem value="port_only">
                      <div className="flex items-center gap-2">
                        <Server className="h-4 w-4" />
                        {language === 'tr' ? 'Port Tarama' : 'Port Scan Only'}
                      </div>
                    </SelectItem>
                    <SelectItem value="dns_recursive">
                      <div className="flex items-center gap-2">
                        <Globe className="h-4 w-4" />
                        {language === 'tr' ? 'Recursive DNS' : 'Recursive DNS'}
                      </div>
                    </SelectItem>
                  </SelectContent>
                </Select>
                {config.scan_type === 'port_only' && (
                  <p className="text-xs text-muted-foreground">
                    {language === 'tr' 
                      ? 'Sadece açık portları tarar ve raporlar. CVE/SSL kontrolü yapılmaz.'
                      : 'Only scans and reports open ports. No CVE/SSL checks.'}
                  </p>
                )}
                {config.scan_type === 'dns_recursive' && (
                  <p className="text-xs text-muted-foreground">
                    {language === 'tr' 
                      ? 'DNS sunucusunun recursive sorguları kabul edip etmediğini kontrol eder. Sadece IP ve Prefix hedeflerle çalışır.'
                      : 'Checks if DNS server accepts recursive queries. Only works with IP and Prefix targets.'}
                  </p>
                )}
              </div>

              {/* Port Range */}
              {config.scan_type === 'stealth' && (
                <div className="space-y-2">
                  <Label>{t('port_range')}</Label>
                  <Input
                    value={config.port_range}
                    onChange={(e) => setConfig({ ...config, port_range: e.target.value })}
                    placeholder="1-65535"
                    data-testid="port-range-input"
                    className="mono"
                  />
                </div>
              )}

              {/* Checkboxes */}
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <Checkbox
                    id="check_ssl"
                    checked={config.check_ssl}
                    onCheckedChange={(v) => setConfig({ ...config, check_ssl: v })}
                    data-testid="check-ssl-checkbox"
                  />
                  <Label htmlFor="check_ssl" className="flex items-center gap-2 cursor-pointer">
                    <Lock className="h-4 w-4 text-muted-foreground" />
                    {t('check_ssl')}
                  </Label>
                </div>

                <div className="flex items-center gap-3">
                  <Checkbox
                    id="check_cve"
                    checked={config.check_cve}
                    onCheckedChange={(v) => setConfig({ ...config, check_cve: v })}
                    data-testid="check-cve-checkbox"
                  />
                  <Label htmlFor="check_cve" className="flex items-center gap-2 cursor-pointer">
                    <Shield className="h-4 w-4 text-muted-foreground" />
                    {t('check_cve')}
                  </Label>
                </div>

                <div className="flex items-center gap-3">
                  <Checkbox
                    id="active_checks"
                    checked={config.active_checks}
                    onCheckedChange={(v) => setConfig({ ...config, active_checks: v })}
                    data-testid="active-checks-checkbox"
                  />
                  <Label htmlFor="active_checks" className="flex items-center gap-2 cursor-pointer">
                    <Radar className="h-4 w-4 text-muted-foreground" />
                    Active Checks (SQLi, XSS, etc.)
                  </Label>
                </div>

                <div className="flex items-center gap-3">
                  <Checkbox
                    id="pci_compliance"
                    checked={config.pci_compliance}
                    onCheckedChange={(v) => setConfig({ ...config, pci_compliance: v })}
                    data-testid="pci-checkbox"
                  />
                  <Label htmlFor="pci_compliance" className="flex items-center gap-2 cursor-pointer">
                    <Search className="h-4 w-4 text-muted-foreground" />
                    {t('pci_compliance')}
                  </Label>
                </div>
              </div>

              {/* Risk Assessment Settings */}
              <div className="space-y-4 pt-4 border-t">
                <Label className="text-sm font-medium">Risk Assessment</Label>
                
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Exposure Level</Label>
                  <Select
                    value={config.exposure_level}
                    onValueChange={(v) => setConfig({ ...config, exposure_level: v })}
                  >
                    <SelectTrigger data-testid="exposure-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="internet">Internet (Public)</SelectItem>
                      <SelectItem value="dmz">DMZ</SelectItem>
                      <SelectItem value="internal">Internal Network</SelectItem>
                      <SelectItem value="isolated">Isolated/Air-gapped</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">Data Sensitivity</Label>
                  <Select
                    value={config.data_sensitivity}
                    onValueChange={(v) => setConfig({ ...config, data_sensitivity: v })}
                  >
                    <SelectTrigger data-testid="sensitivity-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="normal">Normal</SelectItem>
                      <SelectItem value="sensitive">Sensitive (PII, Financial)</SelectItem>
                      <SelectItem value="critical">Critical (Healthcare, Gov)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Submit Button */}
              <Button
                type="submit"
                className="w-full"
                disabled={submitting || selectedTargets.length === 0 || !selectedAgent || !hasOnlineAgent}
                data-testid="start-scan-btn"
              >
                {submitting ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 spinner" />
                    {language === 'tr' ? 'Başlatılıyor...' : 'Starting...'}
                  </>
                ) : (
                  <>
                    <Play className="mr-2 h-4 w-4" />
                    {t('start_scan')}
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </div>
      </form>
    </div>
  );
}
