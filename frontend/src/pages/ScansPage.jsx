import { useEffect, useState } from 'react';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Progress } from '../components/ui/progress';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '../components/ui/alert-dialog';
import {
  Radar,
  Plus,
  Trash2,
  Eye,
  StopCircle,
  FileText,
  Loader2,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from 'lucide-react';
import { toast } from 'sonner';

const STATUS_CONFIG = {
  pending: { icon: Clock, color: 'bg-muted text-muted-foreground', label: 'pending' },
  running: { icon: Loader2, color: 'bg-blue-500/20 text-blue-400', label: 'running', animate: true },
  completed: { icon: CheckCircle, color: 'bg-green-500/20 text-green-400', label: 'completed' },
  failed: { icon: XCircle, color: 'bg-red-500/20 text-red-400', label: 'failed' },
  cancelled: { icon: AlertTriangle, color: 'bg-yellow-500/20 text-yellow-400', label: 'cancelled' },
};

export default function ScansPage() {
  const { api } = useAuth();
  const { t } = useLanguage();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchScans = async () => {
    try {
      const response = await api.get('/scans');
      setScans(response.data);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = async (id) => {
    try {
      await api.post(`/scans/${id}/cancel`);
      toast.success(t('success'));
      fetchScans();
    } catch (error) {
      toast.error(error.response?.data?.detail || t('error'));
    }
  };

  const handleDelete = async (id) => {
    try {
      await api.delete(`/scans/${id}`);
      toast.success(t('success'));
      fetchScans();
    } catch (error) {
      toast.error(t('error'));
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96" data-testid="scans-loading">
        <Loader2 className="h-8 w-8 spinner text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="scans-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">{t('scans')}</h1>
          <p className="text-muted-foreground">View and manage your vulnerability scans</p>
        </div>
        <Link to="/scans/new">
          <Button data-testid="new-scan-btn">
            <Plus className="mr-2 h-4 w-4" />
            {t('new_scan')}
          </Button>
        </Link>
      </div>

      {/* Scans Table */}
      <Card data-testid="scans-table-card">
        <CardContent className="p-0">
          {scans.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('scan_name')}</TableHead>
                  <TableHead>{t('status')}</TableHead>
                  <TableHead>{t('progress')}</TableHead>
                  <TableHead>{t('vulnerabilities')}</TableHead>
                  <TableHead>{t('created')}</TableHead>
                  <TableHead className="text-right">{t('actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => {
                  const statusConfig = STATUS_CONFIG[scan.status] || STATUS_CONFIG.pending;
                  const StatusIcon = statusConfig.icon;
                  return (
                    <TableRow key={scan.id} data-testid={`scan-row-${scan.id}`}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          <Radar className="h-4 w-4 text-muted-foreground" />
                          {scan.name}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={statusConfig.color}>
                          <StatusIcon className={`mr-1 h-3 w-3 ${statusConfig.animate ? 'spinner' : ''}`} />
                          {t(statusConfig.label)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2 w-32">
                          <Progress value={scan.progress} className="h-2" />
                          <span className="text-sm text-muted-foreground mono">{scan.progress}%</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2 text-sm">
                          {scan.critical_count > 0 && (
                            <span className="text-[#EF4444] mono font-medium">{scan.critical_count}C</span>
                          )}
                          {scan.high_count > 0 && (
                            <span className="text-[#F97316] mono font-medium">{scan.high_count}H</span>
                          )}
                          {scan.medium_count > 0 && (
                            <span className="text-[#F59E0B] mono font-medium">{scan.medium_count}M</span>
                          )}
                          {scan.low_count > 0 && (
                            <span className="text-[#EAB308] mono font-medium">{scan.low_count}L</span>
                          )}
                          {scan.info_count > 0 && (
                            <span className="text-[#3B82F6] mono font-medium">{scan.info_count}I</span>
                          )}
                          {scan.total_vulnerabilities === 0 && (
                            <span className="text-muted-foreground">-</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm mono">
                        {new Date(scan.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          <Link to={`/scans/${scan.id}`}>
                            <Button
                              variant="ghost"
                              size="icon"
                              data-testid={`view-scan-${scan.id}`}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          </Link>
                          {scan.status === 'completed' && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => window.open(`${process.env.REACT_APP_BACKEND_URL}/api/scans/${scan.id}/report?format=pdf`, '_blank')}
                              data-testid={`report-scan-${scan.id}`}
                            >
                              <FileText className="h-4 w-4" />
                            </Button>
                          )}
                          {scan.status === 'running' && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleCancel(scan.id)}
                              className="text-yellow-500 hover:text-yellow-500"
                              data-testid={`cancel-scan-${scan.id}`}
                            >
                              <StopCircle className="h-4 w-4" />
                            </Button>
                          )}
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="text-destructive hover:text-destructive"
                                disabled={scan.status === 'running'}
                                data-testid={`delete-scan-${scan.id}`}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>{t('confirm_delete')}</AlertDialogTitle>
                                <AlertDialogDescription>
                                  This will permanently delete the scan "{scan.name}" and all its results.
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>{t('cancel')}</AlertDialogCancel>
                                <AlertDialogAction
                                  onClick={() => handleDelete(scan.id)}
                                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                >
                                  {t('delete')}
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          ) : (
            <div className="text-center py-12 text-muted-foreground">
              <Radar className="h-12 w-12 mx-auto mb-4 opacity-30" />
              <p className="text-lg">{t('no_data')}</p>
              <p className="text-sm">Start your first scan to find vulnerabilities</p>
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
