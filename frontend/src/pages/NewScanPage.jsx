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
import { ScrollArea } from '../components/ui/scroll-area';
import { Badge } from '../components/ui/badge';
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
  const { t } = useLanguage();
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [selectedTargets, setSelectedTargets] = useState([]);
  const [scanName, setScanName] = useState('');
  const [config, setConfig] = useState({
    scan_type: 'quick',
    port_range: '1-1000',
    check_ssl: true,
    check_cve: true,
    pci_compliance: true,
  });

  useEffect(() => {
    fetchTargets();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchTargets = async () => {
    try {
      const response = await api.get('/targets');
      setTargets(response.data.filter(t => t.is_active !== false));
    } catch (error) {
      toast.error(t('error'));
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
      toast.error('Please select at least one target');
      return;
    }

    if (!scanName.trim()) {
      toast.error('Please enter a scan name');
      return;
    }

    setSubmitting(true);

    try {
      const response = await api.post('/scans', {
        name: scanName,
        target_ids: selectedTargets,
        config: {
          scan_type: config.scan_type,
          port_range: config.scan_type === 'quick' ? '1-100' : config.scan_type === 'full' ? '1-65535' : config.port_range,
          check_ssl: config.check_ssl,
          check_cve: config.check_cve,
          pci_compliance: config.pci_compliance,
        },
      });

      toast.success('Scan started successfully');
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
          <p className="text-muted-foreground">Configure and start a new vulnerability scan</p>
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
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
                placeholder="Enter scan name..."
                required
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
                <ScrollArea className="h-80">
                  <div className="space-y-2 pr-4">
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
                          <Checkbox
                            checked={isSelected}
                            onCheckedChange={() => handleTargetToggle(target.id)}
                          />
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
                </ScrollArea>
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
                <Label>Scan Type</Label>
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
                  </SelectContent>
                </Select>
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

              {/* Submit Button */}
              <Button
                type="submit"
                className="w-full"
                disabled={submitting || selectedTargets.length === 0}
                data-testid="start-scan-btn"
              >
                {submitting ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 spinner" />
                    Starting...
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
