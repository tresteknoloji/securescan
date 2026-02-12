import { useEffect, useState } from 'react';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table';
import { FileText, Download, Eye, Loader2, Radar } from 'lucide-react';
import { toast } from 'sonner';

const STATUS_COLORS = {
  completed: 'bg-green-500/20 text-green-400',
  failed: 'bg-red-500/20 text-red-400',
};

export default function ReportsPage() {
  const { api, token } = useAuth();
  const { t } = useLanguage();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await api.get('/scans');
      // Filter only completed scans
      setScans(response.data.filter(s => s.status === 'completed'));
    } catch (error) {
      toast.error(t('error'));
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (scanId, format) => {
    window.open(
      `${process.env.REACT_APP_BACKEND_URL}/api/scans/${scanId}/report?format=${format}`,
      '_blank'
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96" data-testid="reports-loading">
        <Loader2 className="h-8 w-8 spinner text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="reports-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">{t('reports')}</h1>
          <p className="text-muted-foreground">Download scan reports in HTML or PDF format</p>
        </div>
      </div>

      {/* Reports Table */}
      <Card data-testid="reports-table-card">
        <CardContent className="p-0">
          {scans.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('scan_name')}</TableHead>
                  <TableHead>{t('vulnerabilities')}</TableHead>
                  <TableHead>{t('created')}</TableHead>
                  <TableHead className="text-right">{t('actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => (
                  <TableRow key={scan.id} data-testid={`report-row-${scan.id}`}>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <FileText className="h-4 w-4 text-muted-foreground" />
                        {scan.name}
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
                          <span className="text-green-400">Clean</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm mono">
                      {new Date(scan.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Link to={`/scans/${scan.id}`}>
                          <Button
                            variant="ghost"
                            size="sm"
                            data-testid={`view-report-${scan.id}`}
                          >
                            <Eye className="mr-2 h-4 w-4" />
                            {t('details')}
                          </Button>
                        </Link>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleDownload(scan.id, 'html')}
                          data-testid={`download-html-${scan.id}`}
                        >
                          <Download className="mr-2 h-4 w-4" />
                          HTML
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => handleDownload(scan.id, 'pdf')}
                          data-testid={`download-pdf-${scan.id}`}
                        >
                          <Download className="mr-2 h-4 w-4" />
                          PDF
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="text-center py-12 text-muted-foreground">
              <FileText className="h-12 w-12 mx-auto mb-4 opacity-30" />
              <p className="text-lg">{t('no_data')}</p>
              <p className="text-sm">Complete a scan to generate reports</p>
              <Link to="/scans/new">
                <Button className="mt-4" variant="outline">
                  <Radar className="mr-2 h-4 w-4" />
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
