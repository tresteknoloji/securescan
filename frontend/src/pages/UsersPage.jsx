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
import { Users, Plus, Trash2, Edit, UserCircle, Loader2, Shield, Store, User } from 'lucide-react';
import { toast } from 'sonner';

const ROLE_CONFIG = {
  admin: { icon: Shield, color: 'bg-red-500/20 text-red-400', label: 'admin' },
  reseller: { icon: Store, color: 'bg-purple-500/20 text-purple-400', label: 'reseller' },
  customer: { icon: User, color: 'bg-blue-500/20 text-blue-400', label: 'customer' },
};

export default function UsersPage() {
  const { api, user: currentUser, isAdmin, isReseller } = useAuth();
  const { t } = useLanguage();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editUser, setEditUser] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    role: 'customer',
    max_customers: '',
    max_targets: '',
    monthly_scan_limit: '',
  });

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await api.get('/users');
      setUsers(response.data);
    } catch (error) {
      toast.error(t('error'));
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const data = {
        name: formData.name,
        ...(editUser ? {} : {
          email: formData.email,
          password: formData.password,
          role: isReseller ? 'customer' : formData.role,
        }),
        max_customers: formData.max_customers ? parseInt(formData.max_customers) : null,
        max_targets: formData.max_targets ? parseInt(formData.max_targets) : null,
        monthly_scan_limit: formData.monthly_scan_limit ? parseInt(formData.monthly_scan_limit) : null,
      };

      if (editUser) {
        await api.put(`/users/${editUser.id}`, data);
      } else {
        await api.post('/users', data);
      }
      
      toast.success(t('success'));
      setDialogOpen(false);
      setEditUser(null);
      resetForm();
      fetchUsers();
    } catch (error) {
      toast.error(error.response?.data?.detail || t('error'));
    }
  };

  const handleDelete = async (id) => {
    try {
      await api.delete(`/users/${id}`);
      toast.success(t('success'));
      fetchUsers();
    } catch (error) {
      toast.error(t('error'));
    }
  };

  const resetForm = () => {
    setFormData({
      name: '',
      email: '',
      password: '',
      role: 'customer',
      max_customers: '',
      max_targets: '',
      monthly_scan_limit: '',
    });
  };

  const openEditDialog = (user) => {
    setEditUser(user);
    setFormData({
      name: user.name,
      email: user.email,
      password: '',
      role: user.role,
      max_customers: user.max_customers?.toString() || '',
      max_targets: user.max_targets?.toString() || '',
      monthly_scan_limit: user.monthly_scan_limit?.toString() || '',
    });
    setDialogOpen(true);
  };

  const openNewDialog = () => {
    setEditUser(null);
    resetForm();
    setDialogOpen(true);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96" data-testid="users-loading">
        <Loader2 className="h-8 w-8 spinner text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="users-page">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold">{t('users')}</h1>
          <p className="text-muted-foreground">
            {isAdmin ? 'Manage all users and resellers' : 'Manage your customers'}
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={openNewDialog} data-testid="add-user-btn">
              <Plus className="mr-2 h-4 w-4" />
              {isReseller ? t('customers') : t('users')}
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>
                {editUser ? `${t('edit')} ${editUser.name}` : isReseller ? 'Add Customer' : 'Add User'}
              </DialogTitle>
              <DialogDescription>
                {editUser ? 'Update user details and limits' : 'Create a new user account'}
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleSubmit}>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="name">{t('name')}</Label>
                  <Input
                    id="name"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="John Doe"
                    required
                    data-testid="user-name-input"
                  />
                </div>
                {!editUser && (
                  <>
                    <div className="space-y-2">
                      <Label htmlFor="email">{t('email')}</Label>
                      <Input
                        id="email"
                        type="email"
                        value={formData.email}
                        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                        placeholder="john@example.com"
                        required
                        data-testid="user-email-input"
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="password">{t('password')}</Label>
                      <Input
                        id="password"
                        type="password"
                        value={formData.password}
                        onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                        placeholder="••••••••"
                        required
                        minLength={6}
                        data-testid="user-password-input"
                      />
                    </div>
                    {isAdmin && (
                      <div className="space-y-2">
                        <Label htmlFor="role">{t('role')}</Label>
                        <Select
                          value={formData.role}
                          onValueChange={(v) => setFormData({ ...formData, role: v })}
                        >
                          <SelectTrigger data-testid="user-role-select">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="customer">{t('customer')}</SelectItem>
                            <SelectItem value="reseller">{t('reseller')}</SelectItem>
                            <SelectItem value="admin">{t('admin')}</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                  </>
                )}
                
                {/* Limits */}
                <div className="border-t border-border pt-4">
                  <p className="text-sm font-medium mb-3">Limits (leave empty for unlimited)</p>
                  
                  {(formData.role === 'reseller' || editUser?.role === 'reseller') && (
                    <div className="space-y-2 mb-3">
                      <Label htmlFor="max_customers">{t('customers_limit')}</Label>
                      <Input
                        id="max_customers"
                        type="number"
                        value={formData.max_customers}
                        onChange={(e) => setFormData({ ...formData, max_customers: e.target.value })}
                        placeholder="Unlimited"
                        data-testid="max-customers-input"
                      />
                    </div>
                  )}
                  
                  <div className="space-y-2 mb-3">
                    <Label htmlFor="max_targets">{t('targets_limit')}</Label>
                    <Input
                      id="max_targets"
                      type="number"
                      value={formData.max_targets}
                      onChange={(e) => setFormData({ ...formData, max_targets: e.target.value })}
                      placeholder="Unlimited"
                      data-testid="max-targets-input"
                    />
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="monthly_scan_limit">{t('monthly_limit')}</Label>
                    <Input
                      id="monthly_scan_limit"
                      type="number"
                      value={formData.monthly_scan_limit}
                      onChange={(e) => setFormData({ ...formData, monthly_scan_limit: e.target.value })}
                      placeholder="Unlimited"
                      data-testid="monthly-limit-input"
                    />
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>
                  {t('cancel')}
                </Button>
                <Button type="submit" data-testid="user-submit-btn">
                  {t('save')}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Users Table */}
      <Card data-testid="users-table-card">
        <CardContent className="p-0">
          {users.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('name')}</TableHead>
                  <TableHead>{t('email')}</TableHead>
                  <TableHead>{t('role')}</TableHead>
                  <TableHead>Limits</TableHead>
                  <TableHead>{t('status')}</TableHead>
                  <TableHead className="text-right">{t('actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((user) => {
                  const roleConfig = ROLE_CONFIG[user.role] || ROLE_CONFIG.customer;
                  const RoleIcon = roleConfig.icon;
                  return (
                    <TableRow key={user.id} data-testid={`user-row-${user.id}`}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          <UserCircle className="h-4 w-4 text-muted-foreground" />
                          {user.name}
                        </div>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{user.email}</TableCell>
                      <TableCell>
                        <Badge className={roleConfig.color}>
                          <RoleIcon className="mr-1 h-3 w-3" />
                          {t(roleConfig.label)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        <div className="space-y-1">
                          {user.max_targets && (
                            <div>{t('targets')}: {user.max_targets}</div>
                          )}
                          {user.monthly_scan_limit && (
                            <div>{t('scans')}: {user.scans_used_this_month || 0}/{user.monthly_scan_limit}</div>
                          )}
                          {!user.max_targets && !user.monthly_scan_limit && (
                            <span>{t('unlimited')}</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={user.is_active ? 'default' : 'secondary'}>
                          {user.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => openEditDialog(user)}
                            disabled={user.id === currentUser?.id}
                            data-testid={`edit-user-${user.id}`}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="text-destructive hover:text-destructive"
                                disabled={user.id === currentUser?.id}
                                data-testid={`delete-user-${user.id}`}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>{t('confirm_delete')}</AlertDialogTitle>
                                <AlertDialogDescription>
                                  This will permanently delete the user "{user.name}".
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>{t('cancel')}</AlertDialogCancel>
                                <AlertDialogAction
                                  onClick={() => handleDelete(user.id)}
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
              <Users className="h-12 w-12 mx-auto mb-4 opacity-30" />
              <p className="text-lg">{t('no_data')}</p>
              <Button onClick={openNewDialog} className="mt-4" variant="outline">
                <Plus className="mr-2 h-4 w-4" />
                Add First User
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
