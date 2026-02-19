import { useState, useEffect, useCallback } from 'react';
import { useAuth, useLanguage } from '../contexts/AppContext';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
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
} from '../components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../components/ui/alert-dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '../components/ui/table';
import { toast } from 'sonner';
import {
  HardDrive,
  Plus,
  Trash2,
  RefreshCw,
  Copy,
  Terminal,
  Wifi,
  WifiOff,
  Settings,
  Play,
  Network,
  Clock,
  Server,
  Key,
} from 'lucide-react';

const API_URL = process.env.REACT_APP_BACKEND_URL;

export default function AgentsPage() {
  const { token } = useAuth();
  const { t, language } = useLanguage();
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showTokenDialog, setShowTokenDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [newAgentToken, setNewAgentToken] = useState(null);
  const [newAgent, setNewAgent] = useState({ name: '', internal_networks: '' });

  const tr = {
    agents: 'Agentlar',
    agents_desc: 'Uzak ağlarda tarama yapmak için agent yönetimi',
    add_agent: 'Yeni Agent',
    no_agents: 'Henüz agent eklenmemiş',
    no_agents_desc: 'Dahili ağlarınızı taramak için bir agent ekleyin',
    agent_name: 'Agent Adı',
    agent_name_placeholder: 'Örn: Ofis Ağı, AWS VPC',
    internal_networks: 'Dahili Ağlar',
    internal_networks_placeholder: '192.168.1.0/24, 10.0.0.0/8',
    internal_networks_hint: 'Virgülle ayrılmış CIDR formatında ağlar',
    create_agent: 'Agent Oluştur',
    cancel: 'İptal',
    online: 'Çevrimiçi',
    offline: 'Çevrimdışı',
    busy: 'Meşgul',
    last_seen: 'Son Görülme',
    networks: 'Ağlar',
    tools: 'Araçlar',
    actions: 'İşlemler',
    delete_agent: 'Agentı Sil',
    delete_confirm: 'Bu agentı silmek istediğinizden emin misiniz?',
    delete_warning: 'Bu işlem geri alınamaz. Agent sunucudan kaldırılacak.',
    agent_created: 'Agent Başarıyla Oluşturuldu',
    agent_created_desc: 'Aşağıdaki kurulum komutunu sunucunuzda çalıştırın',
    install_command: 'Kurulum Komutu',
    copy_command: 'Komutu Kopyala',
    token_warning: 'Bu token sadece bir kez gösterilir!',
    close: 'Kapat',
    regenerate_token: 'Tokeni Yenile',
    send_command: 'Komut Gönder',
    health_check: 'Sağlık Kontrolü',
    install_nmap: 'Nmap Kur',
    system_info: 'Sistem Bilgisi',
    command_sent: 'Komut gönderildi',
    agent_deleted: 'Agent silindi',
    copied: 'Kopyalandı',
    never: 'Hiç',
    os_info: 'İşletim Sistemi',
    version: 'Versiyon',
    unknown: 'Bilinmiyor',
  };

  const en = {
    agents: 'Agents',
    agents_desc: 'Manage agents for remote network scanning',
    add_agent: 'New Agent',
    no_agents: 'No agents yet',
    no_agents_desc: 'Add an agent to scan your internal networks',
    agent_name: 'Agent Name',
    agent_name_placeholder: 'E.g: Office Network, AWS VPC',
    internal_networks: 'Internal Networks',
    internal_networks_placeholder: '192.168.1.0/24, 10.0.0.0/8',
    internal_networks_hint: 'Comma-separated networks in CIDR format',
    create_agent: 'Create Agent',
    cancel: 'Cancel',
    online: 'Online',
    offline: 'Offline',
    busy: 'Busy',
    last_seen: 'Last Seen',
    networks: 'Networks',
    tools: 'Tools',
    actions: 'Actions',
    delete_agent: 'Delete Agent',
    delete_confirm: 'Are you sure you want to delete this agent?',
    delete_warning: 'This action cannot be undone. The agent will be removed from the server.',
    agent_created: 'Agent Created Successfully',
    agent_created_desc: 'Run the installation command below on your server',
    install_command: 'Installation Command',
    copy_command: 'Copy Command',
    token_warning: 'This token is only shown once!',
    close: 'Close',
    regenerate_token: 'Regenerate Token',
    send_command: 'Send Command',
    health_check: 'Health Check',
    install_nmap: 'Install Nmap',
    system_info: 'System Info',
    command_sent: 'Command sent',
    agent_deleted: 'Agent deleted',
    copied: 'Copied',
    never: 'Never',
    os_info: 'Operating System',
    version: 'Version',
    unknown: 'Unknown',
  };

  const txt = language === 'tr' ? tr : en;

  const fetchAgents = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/api/agents`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setAgents(data);
      }
    } catch (error) {
      console.error('Error fetching agents:', error);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchAgents();
    // Poll for status updates every 10 seconds
    const interval = setInterval(fetchAgents, 10000);
    return () => clearInterval(interval);
  }, [fetchAgents]);

  const handleCreateAgent = async () => {
    if (!newAgent.name.trim()) {
      toast.error(language === 'tr' ? 'Agent adı gerekli' : 'Agent name is required');
      return;
    }

    try {
      const networks = newAgent.internal_networks
        .split(',')
        .map(n => n.trim())
        .filter(n => n);

      const res = await fetch(`${API_URL}/api/agents`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: newAgent.name,
          internal_networks: networks,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setNewAgentToken(data);
        setShowCreateDialog(false);
        setShowTokenDialog(true);
        setNewAgent({ name: '', internal_networks: '' });
        fetchAgents();
      } else {
        const error = await res.json();
        toast.error(error.detail || 'Error creating agent');
      }
    } catch (error) {
      toast.error('Error creating agent');
    }
  };

  const handleDeleteAgent = async () => {
    if (!selectedAgent) return;

    try {
      const res = await fetch(`${API_URL}/api/agents/${selectedAgent.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });

      if (res.ok) {
        toast.success(txt.agent_deleted);
        setShowDeleteDialog(false);
        setSelectedAgent(null);
        fetchAgents();
      }
    } catch (error) {
      toast.error('Error deleting agent');
    }
  };

  const handleSendCommand = async (agentId, commandType) => {
    try {
      const res = await fetch(
        `${API_URL}/api/agents/${agentId}/send-command?command_type=${commandType}`,
        {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (res.ok) {
        toast.success(txt.command_sent);
        setTimeout(fetchAgents, 2000);
      } else {
        const error = await res.json();
        toast.error(error.detail || 'Error sending command');
      }
    } catch (error) {
      toast.error('Error sending command');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success(txt.copied);
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'online':
        return (
          <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
            <Wifi className="w-3 h-3 mr-1" />
            {txt.online}
          </Badge>
        );
      case 'busy':
        return (
          <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">
            <RefreshCw className="w-3 h-3 mr-1 animate-spin" />
            {txt.busy}
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" className="text-muted-foreground">
            <WifiOff className="w-3 h-3 mr-1" />
            {txt.offline}
          </Badge>
        );
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return txt.never;
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return language === 'tr' ? 'Az önce' : 'Just now';
    if (diffMins < 60) return `${diffMins} ${language === 'tr' ? 'dk önce' : 'min ago'}`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)} ${language === 'tr' ? 'saat önce' : 'hours ago'}`;
    return date.toLocaleDateString();
  };

  return (
    <div className="space-y-6" data-testid="agents-page">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold" data-testid="agents-title">{txt.agents}</h1>
          <p className="text-muted-foreground">{txt.agents_desc}</p>
        </div>
        <Button onClick={() => setShowCreateDialog(true)} data-testid="add-agent-btn">
          <Plus className="w-4 h-4 mr-2" />
          {txt.add_agent}
        </Button>
      </div>

      {/* Agents List */}
      {loading ? (
        <Card>
          <CardContent className="py-12 text-center">
            <RefreshCw className="w-8 h-8 animate-spin mx-auto text-muted-foreground" />
          </CardContent>
        </Card>
      ) : agents.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <HardDrive className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">{txt.no_agents}</h3>
            <p className="text-muted-foreground mb-4">{txt.no_agents_desc}</p>
            <Button onClick={() => setShowCreateDialog(true)}>
              <Plus className="w-4 h-4 mr-2" />
              {txt.add_agent}
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{txt.agent_name}</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>{txt.networks}</TableHead>
                <TableHead>{txt.os_info}</TableHead>
                <TableHead>{txt.tools}</TableHead>
                <TableHead>{txt.last_seen}</TableHead>
                <TableHead className="text-right">{txt.actions}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {agents.map((agent) => (
                <TableRow key={agent.id} data-testid={`agent-row-${agent.id}`}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Server className="w-4 h-4 text-primary" />
                      <div>
                        <p className="font-medium">{agent.name}</p>
                        <p className="text-xs text-muted-foreground font-mono">
                          {agent.ip_address || '-'}
                        </p>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>{getStatusBadge(agent.status)}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {agent.internal_networks?.slice(0, 2).map((net, i) => (
                        <Badge key={i} variant="outline" className="text-xs">
                          <Network className="w-3 h-3 mr-1" />
                          {net}
                        </Badge>
                      ))}
                      {agent.internal_networks?.length > 2 && (
                        <Badge variant="outline" className="text-xs">
                          +{agent.internal_networks.length - 2}
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <span className="text-sm">{agent.os_info || txt.unknown}</span>
                    {agent.agent_version && (
                      <p className="text-xs text-muted-foreground">v{agent.agent_version}</p>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {agent.installed_tools?.map((tool, i) => (
                        <Badge key={i} variant="secondary" className="text-xs">
                          {tool}
                        </Badge>
                      ))}
                      {(!agent.installed_tools || agent.installed_tools.length === 0) && (
                        <span className="text-muted-foreground text-xs">-</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <Clock className="w-3 h-3" />
                      {formatDate(agent.last_seen)}
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      {agent.status === 'online' && (
                        <>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleSendCommand(agent.id, 'health_check')}
                            title={txt.health_check}
                          >
                            <Play className="w-4 h-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleSendCommand(agent.id, 'system_info')}
                            title={txt.system_info}
                          >
                            <Settings className="w-4 h-4" />
                          </Button>
                        </>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive"
                        onClick={() => {
                          setSelectedAgent(agent);
                          setShowDeleteDialog(true);
                        }}
                        title={txt.delete_agent}
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Create Agent Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent data-testid="create-agent-dialog">
          <DialogHeader>
            <DialogTitle>{txt.add_agent}</DialogTitle>
            <DialogDescription>
              {language === 'tr'
                ? 'Dahili ağlarınızı taramak için yeni bir agent ekleyin'
                : 'Add a new agent to scan your internal networks'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="agent-name">{txt.agent_name}</Label>
              <Input
                id="agent-name"
                placeholder={txt.agent_name_placeholder}
                value={newAgent.name}
                onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })}
                data-testid="agent-name-input"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="networks">{txt.internal_networks}</Label>
              <Input
                id="networks"
                placeholder={txt.internal_networks_placeholder}
                value={newAgent.internal_networks}
                onChange={(e) => setNewAgent({ ...newAgent, internal_networks: e.target.value })}
                data-testid="agent-networks-input"
              />
              <p className="text-xs text-muted-foreground">{txt.internal_networks_hint}</p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              {txt.cancel}
            </Button>
            <Button onClick={handleCreateAgent} data-testid="create-agent-submit">
              {txt.create_agent}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Token Dialog - Shows install command */}
      <Dialog open={showTokenDialog} onOpenChange={setShowTokenDialog}>
        <DialogContent className="max-w-2xl" data-testid="token-dialog">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-green-400">
              <HardDrive className="w-5 h-5" />
              {txt.agent_created}
            </DialogTitle>
            <DialogDescription>{txt.agent_created_desc}</DialogDescription>
          </DialogHeader>
          {newAgentToken && (
            <div className="space-y-4 py-4">
              <div className="p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/30">
                <div className="flex items-center gap-2 text-yellow-400 mb-2">
                  <Key className="w-4 h-4" />
                  <span className="font-medium">{txt.token_warning}</span>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label>{txt.install_command}</Label>
                <div className="relative">
                  <div className="p-4 rounded-lg bg-muted font-mono text-sm break-all">
                    <Terminal className="w-4 h-4 inline mr-2 text-green-400" />
                    {newAgentToken.install_command}
                  </div>
                  <Button
                    size="sm"
                    variant="secondary"
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(newAgentToken.install_command)}
                  >
                    <Copy className="w-4 h-4 mr-1" />
                    {txt.copy_command}
                  </Button>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-muted/50 text-sm space-y-2">
                <p className="font-medium">
                  {language === 'tr' ? 'Kurulum Adımları:' : 'Installation Steps:'}
                </p>
                <ol className="list-decimal list-inside space-y-1 text-muted-foreground">
                  <li>
                    {language === 'tr'
                      ? 'Hedef Linux sunucusunda root olarak giriş yapın'
                      : 'Login to the target Linux server as root'}
                  </li>
                  <li>
                    {language === 'tr'
                      ? 'Yukarıdaki komutu kopyalayıp terminalde çalıştırın'
                      : 'Copy the command above and run it in the terminal'}
                  </li>
                  <li>
                    {language === 'tr'
                      ? 'Agent otomatik olarak başlayacak ve panele bağlanacak'
                      : 'The agent will start automatically and connect to the panel'}
                  </li>
                </ol>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button onClick={() => setShowTokenDialog(false)}>{txt.close}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent data-testid="delete-agent-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>{txt.delete_confirm}</AlertDialogTitle>
            <AlertDialogDescription>{txt.delete_warning}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{txt.cancel}</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteAgent}
              className="bg-destructive text-destructive-foreground"
              data-testid="confirm-delete-agent"
            >
              {txt.delete_agent}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
