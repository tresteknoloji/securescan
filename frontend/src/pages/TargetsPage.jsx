import { useEffect, useState } from 'react';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { Badge } from '../components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '../components/ui/dialog';
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
import { Target, Plus, Trash2, Edit, Globe, Server, Network, Loader2 } from 'lucide-react';
import { toast } from 'sonner';

const TYPE_ICONS = {
  ip: Server,
  domain: Globe,
  prefix: Network,
};

const TYPE_COLORS = {
  ip: 'bg-blue-500/20 text-blue-400',
  domain: 'bg-green-500/20 text-green-400',
  prefix: 'bg-purple-500/20 text-purple-400',
};

export default function TargetsPage() {
  const { api } = useAuth();
  const { t } = useLanguage();
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editTarget, setEditTarget] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    target_type: 'ip',
    value: '',
    description: '',
  });

  useEffect(() => {
    fetchTargets();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchTargets = async () => {
    try {
      const response = await api.get('/targets');
      setTargets(response.data);
    } catch (error) {
      toast.error('Failed to load targets');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (editTarget) {
        await api.put(`/targets/${editTarget.id}`, {
          name: formData.name,
          description: formData.description,
        });
        toast.success(t('success'));
      } else {
        await api.post('/targets', formData);
        toast.success(t('success'));
      }
      setDialogOpen(false);
      setEditTarget(null);
      setFormData({ name: '', target_type: 'ip', value: '', description: '' });
      fetchTargets();
    } catch (error) {
      toast.error(error.response?.data?.detail || t('error'));
    }
  };

  const handleDelete = async (id) => {
    try {
      await api.delete(`/targets/${id}`);
      toast.success(t('success'));
      fetchTargets();
    } catch (error) {
      toast.error(t('error'));
    }
  };

  const openEditDialog = (target) => {
    setEditTarget(target);
    setFormData({
      name: target.name,
      target_type: target.target_type,
      value: target.value,
      description: target.description || '',
    });
    setDialogOpen(true);
  };

  const openNewDialog = () => {
    setEditTarget(null);
    setFormData({ name: '', target_type: 'ip', value: '', description: '' });
    setDialogOpen(true);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96" data-testid="targets-loading">
        <Loader2 className="h-8 w-8 spinner text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="targets-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">{t('targets')}</h1>
          <p className="text-muted-foreground">Manage your scan targets</p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={openNewDialog} data-testid="add-target-btn">
              <Plus className="mr-2 h-4 w-4" />
              {t('add_target')}
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>
                {editTarget ? t('edit') : t('add_target')}
              </DialogTitle>
              <DialogDescription>
                {editTarget ? 'Update target details' : 'Add a new target for scanning'}
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleSubmit}>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="name">{t('target_name')}</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="Web Server"
                    required
                    data-testid="target-name-input"
                  />
                </div>
                {!editTarget && (
                  <>
                    <div className="space-y-2">
                      <Label htmlFor="type">{t('type')}</Label>
                      <Select
                        value={formData.target_type}
                        onValueChange={(v) => setFormData({ ...formData, target_type: v })}
                      >
                        <SelectTrigger data-testid="target-type-select">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="ip">{t('ip_address')}</SelectItem>
                          <SelectItem value="domain">{t('domain')}</SelectItem>
                          <SelectItem value="prefix">{t('prefix')}</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="value">{t('value')}</Label>
                      <Input
                        id="value"
                        value={formData.value}
                        onChange={(e) => setFormData({ ...formData, value: e.target.value })}
                        placeholder={
                          formData.target_type === 'ip'
                            ? '192.168.1.1'
                            : formData.target_type === 'domain'
                            ? 'example.com'
                            : '192.168.1.0/24'
                        }
                        required
                        data-testid="target-value-input"
                        className="mono"
                      />
                    </div>
                  </>
                )}
                <div className="space-y-2">
                  <Label htmlFor="description">{t('description')}</Label>
                  <Input
                    id="description"
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="Optional description"
                    data-testid="target-description-input"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                  {t('cancel')}
                </Button>
                <Button type="submit" data-testid="target-submit-btn">
                  {t('save')}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Targets Table */}
      <Card data-testid="targets-table-card">
        <CardContent className="p-0">
          {targets.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('target_name')}</TableHead>
                  <TableHead>{t('type')}</TableHead>
                  <TableHead>{t('value')}</TableHead>
                  <TableHead>{t('description')}</TableHead>
                  <TableHead>{t('created')}</TableHead>
                  <TableHead className="text-right">{t('actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((target) => {
                  const TypeIcon = TYPE_ICONS[target.target_type] || Server;
                  return (
                    <TableRow key={target.id} data-testid={`target-row-${target.id}`}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          <Target className="h-4 w-4 text-muted-foreground" />
                          {target.name}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={TYPE_COLORS[target.target_type]}>
                          <TypeIcon className="mr-1 h-3 w-3" />
                          {t(target.target_type === 'ip' ? 'ip_address' : target.target_type)}
                        </Badge>
                      </TableCell>
                      <TableCell className="mono text-sm">{target.value}</TableCell>
                      <TableCell className="text-muted-foreground max-w-xs truncate">
                        {target.description || '-'}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {new Date(target.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openEditDialog(target)}
                            data-testid={`edit-target-${target.id}`}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="text-destructive hover:text-destructive"
                                data-testid={`delete-target-${target.id}`}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>{t('confirm_delete')}</AlertDialogTitle>
                                <AlertDialogDescription>
                                  This will permanently delete the target "{target.name}".
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>{t('cancel')}</AlertDialogCancel>
                                <AlertDialogAction
                                  onClick={() => handleDelete(target.id)}
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
              <Target className="h-12 w-12 mx-auto mb-4 opacity-30" />
              <p className="text-lg">{t('no_data')}</p>
              <p className="text-sm">Add your first target to start scanning</p>
              <Button onClick={openNewDialog} className="mt-4" variant="outline">
                <Plus className="mr-2 h-4 w-4" />
                {t('add_target')}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
