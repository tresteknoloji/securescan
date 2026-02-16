import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Progress } from '../components/ui/progress';
import { ScrollArea } from '../components/ui/scroll-area';
import {
  Radar,
  ArrowLeft,
  FileText,
  StopCircle,
  RefreshCw,
  Loader2,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Shield,
  Server,
  ExternalLink,
  Fingerprint,
  Zap,
  Flame,
} from 'lucide-react';
import { toast } from 'sonner';

const STATUS_CONFIG = {
  pending: { icon: Clock, color: 'bg-muted text-muted-foreground', label: 'pending' },
  running: { icon: Loader2, color: 'bg-blue-500/20 text-blue-400', label: 'running', animate: true },
  completed: { icon: CheckCircle, color: 'bg-green-500/20 text-green-400', label: 'completed' },
  failed: { icon: XCircle, color: 'bg-red-500/20 text-red-400', label: 'failed' },
  cancelled: { icon: AlertTriangle, color: 'bg-yellow-500/20 text-yellow-400', label: 'cancelled' },
};

const SEVERITY_CONFIG = {
  critical: { color: 'severity-critical', icon: AlertTriangle },
  high: { color: 'severity-high', icon: AlertTriangle },
  medium: { color: 'severity-medium', icon: Shield },
  low: { color: 'severity-low', icon: Shield },
  info: { color: 'severity-info', icon: Shield },
};

export default function ScanDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { api } = useAuth();
  const { t } = useLanguage();
  const [scan, setScan] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedSeverity, setSelectedSeverity] = useState('all');

  const fetchScan = useCallback(async () => {
    try {
      const [scanRes, vulnRes] = await Promise.all([
        api.get('/scans/' + id),
        api.get('/scans/' + id + '/vulnerabilities'),
      ]);
      setScan(scanRes.data);
      setVulnerabilities(vulnRes.data);
    } catch (error) {
      toast.error('Failed to load scan');
      navigate('/scans');
    } finally {
      setLoading(false);
    }
  }, [api, id, navigate]);

  useEffect(() => {
    fetchScan();
  }, [fetchScan]);

  useEffect(() => {
    if (!scan || (scan.status !== 'running' && scan.status !== 'pending')) {
      return;
    }
    
    const interval = setInterval(fetchScan, 3000);
    return () => clearInterval(interval);
  }, [scan, fetchScan]);

  const handleCancel = async () => {
    try {
      await api.post('/scans/' + id + '/cancel');
      toast.success('Scan cancelled');
      fetchScan();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Error');
    }
  };

  const handleDownloadReport = (format) => {
    // Get token from localStorage and use download endpoint
    const token = localStorage.getItem('token');
    if (!token) {
      toast.error('Authentication required');
      return;
    }
    window.open(
      process.env.REACT_APP_BACKEND_URL + '/api/scans/' + id + '/report/download?format=' + format + '&token=' + token,
      '_blank'
    );
  };

  const handleRescan = async () => {
    try {
      // Get original scan's target IDs and config
      const targetIds = scan.target_ids || [];
      
      if (targetIds.length === 0) {
        toast.error('No targets found for rescan');
        return;
      }
      
      const newScanData = {
        name: `${scan.name} (Repeat)`,
        target_ids: targetIds,
        config: scan.config || {
          scan_type: 'quick',
          port_range: '1-1000',
          check_ssl: true,
          check_cve: true,
          active_checks: true,
          exposure_level: 'internet',
          data_sensitivity: 'normal',
        }
      };
      
      const response = await api.post('/scans', newScanData);
      toast.success('Rescan started');
      navigate(`/scans/${response.data.id}`);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to start rescan');
    }
  };

  const filteredVulnerabilities = vulnerabilities.filter(
    (v) => selectedSeverity === 'all' || v.severity === selectedSeverity
  );

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sortedVulnerabilities = [...filteredVulnerabilities].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96" data-testid="scan-detail-loading">
        <Loader2 className="h-8 w-8 spinner text-primary" />
      </div>
    );
  }

  if (!scan) return null;

  const statusConfig = STATUS_CONFIG[scan.status] || STATUS_CONFIG.pending;
  const StatusIcon = statusConfig.icon;

  return (
    <div className="space-y-6" data-testid="scan-detail-page">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
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
            <h1 className="text-3xl font-bold">{scan.name}</h1>
            <div className="flex items-center gap-3 mt-1">
              <Badge className={statusConfig.color}>
                <StatusIcon className={'mr-1 h-3 w-3 ' + (statusConfig.animate ? 'spinner' : '')} />
                {t(statusConfig.label)}
              </Badge>
              <span className="text-sm text-muted-foreground mono">
                {new Date(scan.created_at).toLocaleString()}
              </span>
            </div>
          </div>
        </div>
        <div className="flex gap-2">
          {scan.status === 'running' && (
            <Button variant="outline" onClick={handleCancel} data-testid="cancel-scan-btn">
              <StopCircle className="mr-2 h-4 w-4" />
              {t('stop_scan')}
            </Button>
          )}
          {scan.status === 'completed' && (
            <>
              <Button variant="outline" onClick={() => handleDownloadReport('html')} data-testid="download-html-btn">
                <FileText className="mr-2 h-4 w-4" />
                HTML
              </Button>
              <Button onClick={() => handleDownloadReport('pdf')} data-testid="download-pdf-btn">
                <FileText className="mr-2 h-4 w-4" />
                PDF
              </Button>
            </>
          )}
          {scan.status === 'completed' && (
            <Button variant="outline" onClick={handleRescan} data-testid="rescan-btn">
              <RefreshCw className="mr-2 h-4 w-4" />
              {t('rescan') || 'Tekrarla'}
            </Button>
          )}
          <Button variant="ghost" size="icon" onClick={fetchScan} data-testid="refresh-btn">
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {(scan.status === 'running' || scan.status === 'pending') && (
        <Card data-testid="scan-progress-card">
          <CardContent className="py-4">
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <Progress value={scan.progress} className="h-3" />
              </div>
              <span className="text-lg font-bold mono">{scan.progress}%</span>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { key: 'critical', count: scan.critical_count, color: 'text-[#EF4444]' },
          { key: 'high', count: scan.high_count, color: 'text-[#F97316]' },
          { key: 'medium', count: scan.medium_count, color: 'text-[#F59E0B]' },
          { key: 'low', count: scan.low_count, color: 'text-[#EAB308]' },
          { key: 'info', count: scan.info_count, color: 'text-[#3B82F6]' },
        ].map(({ key, count, color }) => (
          <Card
            key={key}
            className={'stat-' + key + ' card-hover cursor-pointer ' + (selectedSeverity === key ? 'ring-2 ring-primary' : '')}
            onClick={() => setSelectedSeverity(selectedSeverity === key ? 'all' : key)}
            data-testid={'stat-' + key}
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {t(key)}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className={'text-3xl font-bold mono ' + color}>{count}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card data-testid="vulnerabilities-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              {t('vulnerabilities')} ({sortedVulnerabilities.length})
            </CardTitle>
            {selectedSeverity !== 'all' && (
              <Button variant="ghost" size="sm" onClick={() => setSelectedSeverity('all')}>
                Show All
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {sortedVulnerabilities.length > 0 ? (
            <ScrollArea className="h-[500px]">
              <div className="space-y-4 pr-4">
                {sortedVulnerabilities.map((vuln) => {
                  const sevConfig = SEVERITY_CONFIG[vuln.severity] || SEVERITY_CONFIG.info;
                  const SeverityIcon = sevConfig.icon;
                  return (
                    <div
                      key={vuln.id}
                      className="border border-border rounded-sm overflow-hidden"
                      data-testid={'vuln-' + vuln.id}
                    >
                      <div className="flex items-center gap-3 p-4 border-b border-border bg-card">
                        <Badge className={sevConfig.color}>
                          <SeverityIcon className="mr-1 h-3 w-3" />
                          {t(vuln.severity)}
                        </Badge>
                        <h4 className="font-medium flex-1">{vuln.title}</h4>
                        <div className="flex items-center gap-2 text-sm text-muted-foreground mono">
                          {vuln.port && (
                            <span className="flex items-center gap-1">
                              <Server className="h-3 w-3" />
                              Port {vuln.port}
                            </span>
                          )}
                          {vuln.service && <Badge variant="outline">{vuln.service}</Badge>}
                        </div>
                      </div>
                      <div className="p-4 space-y-3">
                        <p className="text-sm text-muted-foreground">{vuln.description}</p>
                        {vuln.solution && (
                          <div>
                            <p className="text-sm font-medium text-green-400">{t('solution')}:</p>
                            <p className="text-sm text-muted-foreground">{vuln.solution}</p>
                          </div>
                        )}
                        <div className="flex items-center gap-4 text-sm flex-wrap">
                          {vuln.real_risk_score !== undefined && (
                            <span className={`mono px-2 py-1 rounded font-bold ${
                              vuln.real_risk_score >= 9 ? 'bg-red-500/20 text-red-400' :
                              vuln.real_risk_score >= 7 ? 'bg-orange-500/20 text-orange-400' :
                              vuln.real_risk_score >= 4 ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-blue-500/20 text-blue-400'
                            }`}>
                              Risk: {vuln.real_risk_score}
                            </span>
                          )}
                          {vuln.recommendation_priority && vuln.recommendation_priority <= 2 && (
                            <Badge className="bg-red-500/20 text-red-400 border-red-500/50">
                              P{vuln.recommendation_priority} - Fix Now
                            </Badge>
                          )}
                          {vuln.cve_id && (
                            <span className="mono bg-secondary/50 px-2 py-1 rounded">{vuln.cve_id}</span>
                          )}
                          {vuln.cvss_score && (
                            <span className="text-muted-foreground">
                              CVSS: <span className="font-medium">{vuln.cvss_score}</span>
                            </span>
                          )}
                          {vuln.is_kev && (
                            <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/50">
                              <Flame className="mr-1 h-3 w-3" />
                              KEV
                            </Badge>
                          )}
                          {vuln.is_verified && (
                            <Badge className="bg-green-500/20 text-green-400 border-green-500/50">
                              Verified
                            </Badge>
                          )}
                          {vuln.source === 'active_check' && (
                            <Badge className="bg-purple-500/20 text-purple-400 border-purple-500/50">
                              <Zap className="mr-1 h-3 w-3" />
                              Active Check
                            </Badge>
                          )}
                          {vuln.source === 'cpe_match' && (
                            <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/50">
                              <Fingerprint className="mr-1 h-3 w-3" />
                              CPE Match
                            </Badge>
                          )}
                          <span className="text-muted-foreground mono">Target: {vuln.target_value}</span>
                        </div>
                        {vuln.references && vuln.references.length > 0 && (
                          <div className="flex flex-wrap gap-2">
                            {vuln.references.slice(0, 3).map((ref, idx) => (
                              <a
                                key={idx}
                                href={ref}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs text-primary hover:underline flex items-center gap-1"
                              >
                                <ExternalLink className="h-3 w-3" />
                                Reference {idx + 1}
                              </a>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          ) : (
            <div className="text-center py-12 text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-4 opacity-30" />
              <p>
                {scan.status === 'running' || scan.status === 'pending'
                  ? 'Scanning in progress...'
                  : 'No vulnerabilities found'}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {(scan.status === 'running' || scan.status === 'pending') && (
        <Card data-testid="live-output-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radar className="h-5 w-5 status-running" />
              {t('live_results')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="terminal h-40 overflow-auto">
              <div className="terminal-line">
                <span className="terminal-timestamp">[{new Date().toLocaleTimeString()}]</span>
                <span>Scanning targets... {scan.progress}% complete</span>
              </div>
              {vulnerabilities.slice(-5).map((v, i) => (
                <div key={i} className="terminal-line">
                  <span className="terminal-timestamp">[FOUND]</span>
                  <span style={{ color: v.severity === 'critical' ? '#EF4444' : '#22c55e' }}>
                    {v.severity.toUpperCase()}: {v.title}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
