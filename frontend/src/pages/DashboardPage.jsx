import { useEffect, useState } from 'react';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Progress } from '../components/ui/progress';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import {
  Shield,
  Target,
  Radar,
  AlertTriangle,
  AlertCircle,
  Info,
  TrendingUp,
  Plus,
  ArrowRight,
  Loader2,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

const SEVERITY_COLORS = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#EAB308',
  info: '#3B82F6',
};

const STATUS_COLORS = {
  pending: 'bg-muted text-muted-foreground',
  running: 'bg-blue-500/20 text-blue-400',
  completed: 'bg-green-500/20 text-green-400',
  failed: 'bg-red-500/20 text-red-400',
  cancelled: 'bg-yellow-500/20 text-yellow-400',
};

export default function DashboardPage() {
  const { api } = useAuth();
  const { t } = useLanguage();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const fetchStats = async () => {
    try {
      const response = await api.get('/dashboard/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96" data-testid="dashboard-loading">
        <Loader2 className="h-8 w-8 spinner text-primary" />
      </div>
    );
  }

  const severityData = [
    { name: t('critical'), value: stats?.critical_count || 0, color: SEVERITY_COLORS.critical },
    { name: t('high'), value: stats?.high_count || 0, color: SEVERITY_COLORS.high },
    { name: t('medium'), value: stats?.medium_count || 0, color: SEVERITY_COLORS.medium },
    { name: t('low'), value: stats?.low_count || 0, color: SEVERITY_COLORS.low },
    { name: t('info'), value: stats?.info_count || 0, color: SEVERITY_COLORS.info },
  ].filter(d => d.value > 0);

  const trendData = (stats?.vulnerability_trend || []).reverse().map(item => ({
    date: item.date.split('-').slice(1).join('/'),
    count: item.count,
  }));

  return (
    <div className="space-y-6" data-testid="dashboard-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">{t('dashboard')}</h1>
          <p className="text-muted-foreground">Overview of your security posture</p>
        </div>
        <div className="flex gap-2">
          <Link to="/targets">
            <Button variant="outline" data-testid="add-target-btn">
              <Target className="mr-2 h-4 w-4" />
              {t('add_target')}
            </Button>
          </Link>
          <Link to="/scans/new">
            <Button data-testid="new-scan-btn">
              <Radar className="mr-2 h-4 w-4" />
              {t('new_scan')}
            </Button>
          </Link>
        </div>
      </div>

      {/* Stats Grid - Bento Style */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="stat-critical card-hover" data-testid="stat-critical">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-[#EF4444]" />
              {t('critical')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold mono text-[#EF4444]">
              {stats?.critical_count || 0}
            </div>
          </CardContent>
        </Card>

        <Card className="stat-high card-hover" data-testid="stat-high">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-[#F97316]" />
              {t('high')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold mono text-[#F97316]">
              {stats?.high_count || 0}
            </div>
          </CardContent>
        </Card>

        <Card className="stat-medium card-hover" data-testid="stat-medium">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Info className="h-4 w-4 text-[#F59E0B]" />
              {t('medium')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold mono text-[#F59E0B]">
              {stats?.medium_count || 0}
            </div>
          </CardContent>
        </Card>

        <Card className="stat-info card-hover" data-testid="stat-total">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              {t('total')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold mono">
              {stats?.total_vulnerabilities || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Secondary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="card-hover" data-testid="stat-scans">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              {t('total_scans')}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <div className="text-2xl font-bold">{stats?.total_scans || 0}</div>
            <Radar className="h-8 w-8 text-muted-foreground/30" />
          </CardContent>
        </Card>

        <Card className="card-hover" data-testid="stat-running">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              {t('running_scans')}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <div className="text-2xl font-bold text-primary">
              {stats?.running_scans || 0}
            </div>
            {stats?.running_scans > 0 && (
              <div className="h-3 w-3 rounded-full bg-primary status-running" />
            )}
          </CardContent>
        </Card>

        <Card className="card-hover" data-testid="stat-targets">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              {t('total_targets')}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center justify-between">
            <div className="text-2xl font-bold">{stats?.total_targets || 0}</div>
            <Target className="h-8 w-8 text-muted-foreground/30" />
          </CardContent>
        </Card>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Trend Chart */}
        <Card className="card-hover" data-testid="trend-chart">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              {t('vulnerability_trend')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              {trendData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData}>
                    <defs>
                      <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                    <XAxis dataKey="date" stroke="#64748B" fontSize={12} />
                    <YAxis stroke="#64748B" fontSize={12} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        border: '1px solid #1E293B',
                        borderRadius: '4px',
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="count"
                      stroke="#3B82F6"
                      fillOpacity={1}
                      fill="url(#colorCount)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-muted-foreground">
                  {t('no_data')}
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Severity Distribution */}
        <Card className="card-hover" data-testid="severity-chart">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              {t('vulnerabilities')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              {severityData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0F172A',
                        border: '1px solid #1E293B',
                        borderRadius: '4px',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-muted-foreground">
                  {t('no_data')}
                </div>
              )}
            </div>
            {/* Legend */}
            <div className="flex flex-wrap justify-center gap-4 mt-4">
              {severityData.map((item) => (
                <div key={item.name} className="flex items-center gap-2">
                  <div
                    className="w-3 h-3 rounded-sm"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-sm text-muted-foreground">
                    {item.name}: {item.value}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans */}
      <Card className="card-hover" data-testid="recent-scans">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>{t('recent_scans')}</CardTitle>
          <Link to="/scans">
            <Button variant="ghost" size="sm">
              View all <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </Link>
        </CardHeader>
        <CardContent>
          {stats?.recent_scans?.length > 0 ? (
            <div className="space-y-3">
              {stats.recent_scans.map((scan) => (
                <Link
                  key={scan.id}
                  to={`/scans/${scan.id}`}
                  className="block"
                  data-testid={`recent-scan-${scan.id}`}
                >
                  <div className="flex items-center justify-between p-3 rounded-sm bg-secondary/30 hover:bg-secondary/50 transition-colors">
                    <div className="flex items-center gap-3">
                      <Radar className="h-5 w-5 text-muted-foreground" />
                      <div>
                        <p className="font-medium">{scan.name}</p>
                        <p className="text-sm text-muted-foreground mono">
                          {new Date(scan.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {scan.status === 'running' && (
                        <div className="w-24">
                          <Progress value={scan.progress} className="h-2" />
                        </div>
                      )}
                      <Badge className={STATUS_COLORS[scan.status]}>
                        {t(scan.status)}
                      </Badge>
                      <div className="flex gap-2 text-sm">
                        {scan.critical_count > 0 && (
                          <span className="text-[#EF4444] mono">{scan.critical_count}C</span>
                        )}
                        {scan.high_count > 0 && (
                          <span className="text-[#F97316] mono">{scan.high_count}H</span>
                        )}
                        {scan.medium_count > 0 && (
                          <span className="text-[#F59E0B] mono">{scan.medium_count}M</span>
                        )}
                      </div>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Radar className="h-12 w-12 mx-auto mb-4 opacity-30" />
              <p>{t('no_data')}</p>
              <Link to="/scans/new">
                <Button className="mt-4" variant="outline">
                  <Plus className="mr-2 h-4 w-4" />
                  {t('new_scan')}
                </Button>
              </Link>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
