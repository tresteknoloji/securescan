import { useEffect, useState, useCallback } from 'react';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Input } from '../components/ui/input';
import { Progress } from '../components/ui/progress';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '../components/ui/dialog';
import {
  Database,
  RefreshCw,
  Search,
  AlertTriangle,
  Shield,
  Download,
  Loader2,
  ExternalLink,
  Flame,
  Calendar,
  TrendingUp,
} from 'lucide-react';
import { toast } from 'sonner';

const SEVERITY_CONFIG = {
  critical: { color: 'bg-red-500/20 text-red-400 border-red-500/50', label: 'CRITICAL' },
  high: { color: 'bg-orange-500/20 text-orange-400 border-orange-500/50', label: 'HIGH' },
  medium: { color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50', label: 'MEDIUM' },
  low: { color: 'bg-blue-500/20 text-blue-400 border-blue-500/50', label: 'LOW' },
  info: { color: 'bg-slate-500/20 text-slate-400 border-slate-500/50', label: 'INFO' },
};

export default function CVEDatabasePage() {
  const { api, user } = useAuth();
  const { t } = useLanguage();
  const [stats, setStats] = useState(null);
  const [syncStatus, setSyncStatus] = useState(null);
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searching, setSearching] = useState(false);
  const [selectedCve, setSelectedCve] = useState(null);
  
  // Search filters
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [kevFilter, setKevFilter] = useState('all');
  const [yearFilter, setYearFilter] = useState('all');
  const [pagination, setPagination] = useState({ skip: 0, limit: 50, total: 0 });

  const fetchStats = useCallback(async () => {
    try {
      const res = await api.get('/cve/stats');
      setStats(res.data);
    } catch (error) {
      console.error('Failed to fetch CVE stats:', error);
    }
  }, [api]);

  const fetchSyncStatus = useCallback(async () => {
    try {
      const res = await api.get('/cve/sync-status');
      setSyncStatus(res.data);
    } catch (error) {
      console.error('Failed to fetch sync status:', error);
    }
  }, [api]);

  const searchCves = useCallback(async (resetPagination = false) => {
    setSearching(true);
    try {
      const params = new URLSearchParams();
      if (searchQuery) params.append('q', searchQuery);
      if (severityFilter !== 'all') params.append('severity', severityFilter);
      if (kevFilter === 'kev') params.append('is_kev', 'true');
      if (yearFilter !== 'all') params.append('year', yearFilter);
      
      const skip = resetPagination ? 0 : pagination.skip;
      params.append('skip', skip);
      params.append('limit', pagination.limit);
      
      const res = await api.get('/cve/search?' + params.toString());
      setCves(res.data.results);
      setPagination(prev => ({
        ...prev,
        skip: res.data.skip,
        total: res.data.total
      }));
    } catch (error) {
      toast.error('Search failed');
    } finally {
      setSearching(false);
      setLoading(false);
    }
  }, [api, searchQuery, severityFilter, kevFilter, yearFilter, pagination.skip, pagination.limit]);

  useEffect(() => {
    fetchStats();
    fetchSyncStatus();
    searchCves(true);
  }, []);

  useEffect(() => {
    if (!syncStatus?.is_running) return;
    const interval = setInterval(fetchSyncStatus, 3000);
    return () => clearInterval(interval);
  }, [syncStatus?.is_running, fetchSyncStatus]);

  const handleFullSync = async () => {
    try {
      await api.post('/cve/sync/full');
      toast.success('Full CVE sync started. This may take several hours.');
      fetchSyncStatus();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to start sync');
    }
  };

  const handleIncrementalSync = async () => {
    try {
      await api.post('/cve/sync/incremental?days_back=30');
      toast.success('Incremental sync started');
      fetchSyncStatus();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to start sync');
    }
  };

  const handleKevSync = async () => {
    try {
      const res = await api.post('/cve/sync/kev');
      toast.success(`CISA KEV synced: ${res.data.synced} vulnerabilities`);
      fetchStats();
    } catch (error) {
      toast.error('Failed to sync KEV');
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    searchCves(true);
  };

  const handlePageChange = (newSkip) => {
    setPagination(prev => ({ ...prev, skip: newSkip }));
    setTimeout(() => searchCves(false), 0);
  };

  const fetchCveDetail = async (cveId) => {
    try {
      const res = await api.get('/cve/' + cveId);
      setSelectedCve(res.data);
    } catch (error) {
      toast.error('Failed to load CVE details');
    }
  };

  const isAdmin = user?.role === 'admin';
  const currentYear = new Date().getFullYear();
  const years = Array.from({ length: 10 }, (_, i) => currentYear - i);

  return (
    <div className="space-y-6" data-testid="cve-database-page">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Database className="h-8 w-8 text-primary" />
            CVE Database
          </h1>
          <p className="text-muted-foreground mt-1">
            National Vulnerability Database + CISA KEV
          </p>
        </div>
        {isAdmin && (
          <div className="flex gap-2 flex-wrap">
            <Button
              variant="outline"
              onClick={handleKevSync}
              disabled={syncStatus?.is_running}
              data-testid="sync-kev-btn"
            >
              <Flame className="mr-2 h-4 w-4 text-orange-500" />
              Sync KEV
            </Button>
            <Button
              variant="outline"
              onClick={handleIncrementalSync}
              disabled={syncStatus?.is_running}
              data-testid="sync-incremental-btn"
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Incremental
            </Button>
            <Button
              onClick={handleFullSync}
              disabled={syncStatus?.is_running}
              data-testid="sync-full-btn"
            >
              <Download className="mr-2 h-4 w-4" />
              Full Sync (240K+)
            </Button>
          </div>
        )}
      </div>

      {/* Sync Progress */}
      {syncStatus?.is_running && (
        <Card className="border-primary/50 bg-primary/5" data-testid="sync-progress">
          <CardContent className="py-4">
            <div className="flex items-center gap-4">
              <Loader2 className="h-5 w-5 spinner text-primary" />
              <div className="flex-1">
                <div className="flex justify-between mb-2">
                  <span className="font-medium">{syncStatus.current_source}</span>
                  <span className="text-sm text-muted-foreground mono">
                    {syncStatus.synced.toLocaleString()} / {syncStatus.total.toLocaleString()}
                  </span>
                </div>
                <Progress value={syncStatus.progress} className="h-2" />
              </div>
              <span className="text-lg font-bold mono">{syncStatus.progress}%</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card data-testid="stat-total">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Database className="h-4 w-4" />
              Total CVEs
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold mono text-primary">
              {stats?.total_cves?.toLocaleString() || '0'}
            </div>
          </CardContent>
        </Card>
        
        <Card className="border-orange-500/30" data-testid="stat-kev">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-500" />
              CISA KEV
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold mono text-orange-500">
              {stats?.kev_count?.toLocaleString() || '0'}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Active Exploits</p>
          </CardContent>
        </Card>
        
        <Card className="border-red-500/30" data-testid="stat-critical">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Critical</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold mono text-red-500">
              {stats?.severity_counts?.critical?.toLocaleString() || '0'}
            </div>
          </CardContent>
        </Card>
        
        <Card className="border-orange-500/30" data-testid="stat-high">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">High</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold mono text-orange-400">
              {stats?.severity_counts?.high?.toLocaleString() || '0'}
            </div>
          </CardContent>
        </Card>
        
        <Card className="border-yellow-500/30" data-testid="stat-medium">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Medium</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold mono text-yellow-500">
              {stats?.severity_counts?.medium?.toLocaleString() || '0'}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Year Distribution */}
      {stats?.by_year && Object.keys(stats.by_year).length > 0 && (
        <Card data-testid="year-distribution">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Calendar className="h-5 w-5" />
              CVE Distribution by Year
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2 flex-wrap">
              {Object.entries(stats.by_year).slice(0, 8).map(([year, count]) => (
                <div
                  key={year}
                  className="bg-secondary/50 rounded-md px-4 py-2 text-center min-w-[100px]"
                >
                  <div className="text-lg font-bold mono">{count.toLocaleString()}</div>
                  <div className="text-xs text-muted-foreground">{year}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Search & Filter */}
      <Card data-testid="cve-search">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            Search CVE Database
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSearch} className="space-y-4">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <Input
                  placeholder="Search CVE ID or description (e.g., CVE-2024-1234, Apache, SQL injection)"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  data-testid="search-input"
                />
              </div>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[150px]" data-testid="severity-filter">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>
              <Select value={kevFilter} onValueChange={setKevFilter}>
                <SelectTrigger className="w-[150px]" data-testid="kev-filter">
                  <SelectValue placeholder="KEV Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All CVEs</SelectItem>
                  <SelectItem value="kev">KEV Only</SelectItem>
                </SelectContent>
              </Select>
              <Select value={yearFilter} onValueChange={setYearFilter}>
                <SelectTrigger className="w-[120px]" data-testid="year-filter">
                  <SelectValue placeholder="Year" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Years</SelectItem>
                  {years.map(year => (
                    <SelectItem key={year} value={year.toString()}>{year}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button type="submit" disabled={searching} data-testid="search-btn">
                {searching ? <Loader2 className="h-4 w-4 spinner" /> : <Search className="h-4 w-4" />}
                <span className="ml-2">Search</span>
              </Button>
            </div>
          </form>

          {/* Results */}
          <div className="mt-6">
            <div className="flex justify-between items-center mb-4">
              <span className="text-sm text-muted-foreground">
                {pagination.total.toLocaleString()} results found
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={pagination.skip === 0}
                  onClick={() => handlePageChange(Math.max(0, pagination.skip - pagination.limit))}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={pagination.skip + pagination.limit >= pagination.total}
                  onClick={() => handlePageChange(pagination.skip + pagination.limit)}
                >
                  Next
                </Button>
              </div>
            </div>

            <div className="border rounded-md">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[150px]">CVE ID</TableHead>
                    <TableHead className="w-[100px]">Severity</TableHead>
                    <TableHead className="w-[80px]">CVSS</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead className="w-[100px]">Published</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center py-8">
                        <Loader2 className="h-6 w-6 spinner mx-auto" />
                      </TableCell>
                    </TableRow>
                  ) : cves.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                        No CVEs found
                      </TableCell>
                    </TableRow>
                  ) : (
                    cves.map((cve) => {
                      const sevConfig = SEVERITY_CONFIG[cve.severity] || SEVERITY_CONFIG.info;
                      return (
                        <TableRow
                          key={cve.cve_id}
                          className="cursor-pointer hover:bg-muted/50"
                          onClick={() => fetchCveDetail(cve.cve_id)}
                          data-testid={`cve-row-${cve.cve_id}`}
                        >
                          <TableCell className="font-mono font-medium">
                            <div className="flex items-center gap-2">
                              {cve.cve_id}
                              {cve.is_kev && (
                                <Flame className="h-4 w-4 text-orange-500" title="Known Exploited" />
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge className={sevConfig.color}>{sevConfig.label}</Badge>
                          </TableCell>
                          <TableCell className="mono">
                            {cve.cvss_v3_score || cve.cvss_v2_score || '-'}
                          </TableCell>
                          <TableCell className="max-w-md truncate text-sm text-muted-foreground">
                            {cve.description?.slice(0, 150)}...
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {cve.published_date?.slice(0, 10)}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* CVE Detail Modal */}
      <Dialog open={!!selectedCve} onOpenChange={() => setSelectedCve(null)}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          {selectedCve && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-3">
                  <span className="mono">{selectedCve.cve_id}</span>
                  {selectedCve.is_kev && (
                    <Badge className="bg-orange-500/20 text-orange-400">
                      <Flame className="mr-1 h-3 w-3" />
                      Known Exploited
                    </Badge>
                  )}
                  <Badge className={SEVERITY_CONFIG[selectedCve.severity]?.color}>
                    {selectedCve.severity?.toUpperCase()}
                  </Badge>
                </DialogTitle>
              </DialogHeader>
              
              <div className="space-y-4 mt-4">
                {/* CVSS Scores */}
                <div className="flex gap-4">
                  {selectedCve.cvss_v3_score && (
                    <div className="bg-secondary/50 rounded-md px-4 py-2">
                      <div className="text-xs text-muted-foreground">CVSS v3</div>
                      <div className="text-2xl font-bold mono">{selectedCve.cvss_v3_score}</div>
                    </div>
                  )}
                  {selectedCve.cvss_v2_score && (
                    <div className="bg-secondary/50 rounded-md px-4 py-2">
                      <div className="text-xs text-muted-foreground">CVSS v2</div>
                      <div className="text-2xl font-bold mono">{selectedCve.cvss_v2_score}</div>
                    </div>
                  )}
                  <div className="bg-secondary/50 rounded-md px-4 py-2">
                    <div className="text-xs text-muted-foreground">Published</div>
                    <div className="text-sm font-medium">{selectedCve.published_date?.slice(0, 10)}</div>
                  </div>
                </div>

                {/* KEV Details */}
                {selectedCve.kev_details && (
                  <div className="bg-orange-500/10 border border-orange-500/30 rounded-md p-4">
                    <h4 className="font-medium text-orange-400 flex items-center gap-2 mb-2">
                      <AlertTriangle className="h-4 w-4" />
                      CISA Known Exploited Vulnerability
                    </h4>
                    <div className="space-y-2 text-sm">
                      <p><strong>Vendor:</strong> {selectedCve.kev_details.vendor_project}</p>
                      <p><strong>Product:</strong> {selectedCve.kev_details.product}</p>
                      <p><strong>Required Action:</strong> {selectedCve.kev_details.required_action}</p>
                      <p><strong>Due Date:</strong> {selectedCve.kev_details.due_date}</p>
                      {selectedCve.kev_details.known_ransomware_use !== 'Unknown' && (
                        <p className="text-red-400">
                          <strong>Ransomware Use:</strong> {selectedCve.kev_details.known_ransomware_use}
                        </p>
                      )}
                    </div>
                  </div>
                )}

                {/* Description */}
                <div>
                  <h4 className="font-medium mb-2">Description</h4>
                  <p className="text-sm text-muted-foreground">{selectedCve.description}</p>
                </div>

                {/* Weaknesses */}
                {selectedCve.weaknesses?.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-2">Weaknesses (CWE)</h4>
                    <div className="flex gap-2 flex-wrap">
                      {selectedCve.weaknesses.map((cwe, i) => (
                        <Badge key={i} variant="outline">{cwe}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* CVSS Vector */}
                {selectedCve.cvss_v3_vector && (
                  <div>
                    <h4 className="font-medium mb-2">CVSS Vector</h4>
                    <code className="text-xs bg-secondary/50 px-2 py-1 rounded">
                      {selectedCve.cvss_v3_vector}
                    </code>
                  </div>
                )}

                {/* References */}
                {selectedCve.references?.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-2">References</h4>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {selectedCve.references.slice(0, 10).map((ref, i) => (
                        <a
                          key={i}
                          href={ref.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2 text-sm text-primary hover:underline"
                        >
                          <ExternalLink className="h-3 w-3" />
                          {ref.url?.slice(0, 60)}...
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
