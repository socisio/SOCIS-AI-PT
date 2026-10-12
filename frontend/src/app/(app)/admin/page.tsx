'use client';
import { Suspense, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Users, ClipboardList, Trash2, UserX, UserCheck, Plus, RefreshCw, Loader2 } from 'lucide-react';
import { adminApi, llmApi, settingsApi } from '@/lib/api';
import UsersPanel from '@/components/admin/UsersPanel';
import SettingsShell, { SectionHead, useSection } from '@/components/settings/SettingsShell';
import Icon from '@/components/ui/Icon';
import type { NavGroup } from '@/components/settings/SettingsShell';
import { askConfirm, notify } from '@/lib/dialogs';
import { PROVIDER_OPTIONS, providerLabel } from '@/lib/providers';

type AdminTab = 'users' | 'logs' | 'settings' | 'prompt_templates' | 'plugins';
type AdminSettingsSubtab = 'platform' | 'sso' | 'notifications' | 'tools';

// One level of navigation: the section comes from the URL (?section=...). The existing tab / sub-tab rendering below is driven by
// these two derived values, so every block of working code is kept as it was.
const ADMIN_GROUPS: NavGroup[] = [
  { label: 'People', items: [
    { key: 'users', label: 'Users & roles', icon: 'users' },
    { key: 'auth', label: 'Authentication', icon: 'lock' },
  ] },
  { label: 'Platform', items: [
    { key: 'ai', label: 'AI providers', icon: 'cpu' },
    { key: 'tools', label: 'Tools & MCP', icon: 'terminal' },
    { key: 'delivery', label: 'Notification delivery', icon: 'mail' },
    { key: 'plugins', label: 'Plugins', icon: 'puzzle' },
    { key: 'prompts', label: 'Prompt templates', icon: 'clip' },
  ] },
  { label: 'Governance', items: [{ key: 'audit', label: 'Audit log', icon: 'history' }] },
];

const SECTION_MAP: Record<string, { tab: AdminTab; sub: AdminSettingsSubtab }> = {
  users: { tab: 'users', sub: 'platform' },
  auth: { tab: 'settings', sub: 'sso' },
  ai: { tab: 'settings', sub: 'platform' },
  tools: { tab: 'settings', sub: 'tools' },
  delivery: { tab: 'settings', sub: 'notifications' },
  plugins: { tab: 'plugins', sub: 'platform' },
  prompts: { tab: 'prompt_templates', sub: 'platform' },
  audit: { tab: 'logs', sub: 'platform' },
};

const SUB_HEAD: Record<AdminSettingsSubtab, { title: string; desc: string }> = {
  platform: { title: 'AI providers', desc: 'Model routing: your Ollama server, the providers people can choose in AI chat, and the execution policy.' },
  sso: { title: 'Authentication', desc: 'Single sign-on with Google or Microsoft.' },
  notifications: { title: 'Notification delivery', desc: 'How the platform sends email (SMTP or Microsoft Graph) and notifications.' },
  tools: { title: 'Tools & MCP', desc: 'Which tools the AI chat may call on its own, and how long a real scan may let a tool run. This does not restrict what a scan itself can use — that comes from the scan type or workflow you choose when you start it.' },
};
const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? '';

// Provider labels come from the single shared source (@/lib/providers) — this used to have its own near-duplicate
// map here (differing only in Ollama's exact wording: "Ollama (Remote)" vs the shared file's "Ollama (external)"),
// exactly the kind of inconsistency this whole mechanism exists to remove.

const TOOL_SETTINGS_DEFAULT = {
  tool_timeout_default: 120,
  tool_timeout_nmap: 300,
  tool_timeout_nuclei: 600,
  mcp_nmap_enabled: true,
  mcp_masscan_enabled: true,
  mcp_nuclei_enabled: true,
  mcp_nikto_enabled: true,
  mcp_wpscan_enabled: false,
  mcp_ffuf_enabled: true,
  mcp_gobuster_enabled: true,
  mcp_sqlmap_enabled: true,
  mcp_waf_detection_enabled: true,
  mcp_ssl_enabled: true,
  mcp_jwt_enabled: true,
  mcp_metasploit_enabled: false,
  mcp_poc_enabled: true,
  mcp_cve_enabled: true,
  mcp_cve_lite_enabled: true,
  mcp_epss_enabled: true,
  mcp_cisa_kev_enabled: true,
  mcp_osint_enabled: true,
  mcp_mitre_enabled: true,
  mcp_exploitdb_enabled: true,
  mcp_anomaly_enabled: false,
  mcp_payload_generator_enabled: false,
  mcp_ad_enabled: false,
  mcp_cloud_enabled: true,
  mcp_container_enabled: true,
  mcp_api_security_enabled: true,
  mcp_secrets_enabled: true,
  mcp_dns_deep_enabled: true,
  mcp_crack_enabled: false,
  mcp_compliance_enabled: true,
};

const TOOL_CATEGORIES: Array<{ title: string; items: Array<{ key: string; label: string }> }> = [
  {
    title: 'Network and Web Scanners',
    items: [
      { key: 'mcp_nmap_enabled', label: 'Nmap' },
      { key: 'mcp_masscan_enabled', label: 'Masscan' },
      { key: 'mcp_nuclei_enabled', label: 'Nuclei' },
      { key: 'mcp_nikto_enabled', label: 'Nikto' },
      { key: 'mcp_wpscan_enabled', label: 'WPScan' },
      { key: 'mcp_ffuf_enabled', label: 'ffuf' },
      { key: 'mcp_gobuster_enabled', label: 'Gobuster' },
      { key: 'mcp_sqlmap_enabled', label: 'SQLMap' },
      { key: 'mcp_waf_detection_enabled', label: 'WAF Detection' },
    ],
  },
  {
    title: 'Intelligence and Validation',
    items: [
      { key: 'mcp_ssl_enabled', label: 'SSL Labs' },
      { key: 'mcp_jwt_enabled', label: 'JWT Analyzer' },
      { key: 'mcp_metasploit_enabled', label: 'Metasploit' },
      { key: 'mcp_poc_enabled', label: 'PoC Index' },
      { key: 'mcp_cve_enabled', label: 'CVE Database' },
      { key: 'mcp_cve_lite_enabled', label: 'CVE Lite' },
      { key: 'mcp_epss_enabled', label: 'EPSS' },
      { key: 'mcp_cisa_kev_enabled', label: 'CISA KEV' },
      { key: 'mcp_osint_enabled', label: 'OSINT' },
      { key: 'mcp_mitre_enabled', label: 'MITRE ATT&CK' },
      { key: 'mcp_exploitdb_enabled', label: 'ExploitDB' },
      { key: 'mcp_anomaly_enabled', label: 'Anomaly Detection' },
      { key: 'mcp_payload_generator_enabled', label: 'Payload Generator' },
    ],
  },
  {
    title: 'Active Directory',
    items: [
      { key: 'mcp_ad_enabled', label: 'Active Directory (NetExec/kerbrute)' },
    ],
  },
  {
    title: 'Cloud Recon',
    items: [
      { key: 'mcp_cloud_enabled', label: 'Cloud Recon (bucket enum, fingerprinting, SSRF metadata check)' },
    ],
  },
  {
    title: 'Container & Kubernetes',
    items: [
      { key: 'mcp_container_enabled', label: 'Container & K8s (Trivy image/Dockerfile/manifest scanning)' },
    ],
  },
  {
    title: 'API Security',
    items: [
      { key: 'mcp_api_security_enabled', label: 'API Security (GraphQL introspection, OpenAPI discovery, CORS/misconfig checks)' },
    ],
  },
  {
    title: 'Secrets Scanning',
    items: [
      { key: 'mcp_secrets_enabled', label: 'Secrets Scanning (live credentials in code/config content)' },
    ],
  },
  {
    title: 'DNS Deep',
    items: [
      { key: 'mcp_dns_deep_enabled', label: 'DNS Deep (zone transfer, subdomain takeover, SPF/DKIM/DMARC)' },
    ],
  },
  {
    title: 'Password Cracking',
    items: [
      { key: 'mcp_crack_enabled', label: 'Password Cracking (John the Ripper wordlist attacks)' },
    ],
  },
  {
    title: 'Compliance Mapping',
    items: [
      { key: 'mcp_compliance_enabled', label: 'Compliance Mapping (OWASP Top 10 / PTES / MITRE ATT&CK)' },
    ],
  },
];

function AdminPageInner() {
  const router = useRouter();
  const section = useSection(ADMIN_GROUPS);
  const tab: AdminTab = SECTION_MAP[section].tab;
  const settingsSubtab: AdminSettingsSubtab = SECTION_MAP[section].sub;
  const goSection = (key: string) => router.replace(`/admin?section=${key}`, { scroll: false });
  const [stats, setStats] = useState({ users: 0, projects: 0, scans: 0, vulnerabilities: 0 });
  const [users, setUsers] = useState<any[]>([]);
  const [llmConfigs, setLlmConfigs] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddLlm, setShowAddLlm] = useState(false);
  const [llmForm, setLlmForm] = useState({ name: '', provider: 'ollama_remote', model_name: '', api_url: '', api_key: '', is_default: false });
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  // Fetched model list for a non-Ollama provider (OpenAI/Anthropic/OpenRouter/Grok/Mistral) after the admin enters an
  // API key and clicks "Fetch Models" — separate from availableModels (Ollama's own list) so the existing Ollama
  // flow is untouched.
  const [apiModels, setApiModels] = useState<{ id: string; label: string }[]>([]);
  const [fetchingApiModels, setFetchingApiModels] = useState(false);
  const [apiModelsError, setApiModelsError] = useState<string | null>(null);
  const [loadingModels, setLoadingModels] = useState(false);
  // Settings state
  const [remoteOllamaUrl, setRemoteOllamaUrl] = useState('');
  const [remoteOllamaModel, setRemoteOllamaModel] = useState('');
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsMsg, setSettingsMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [testResult, setTestResult] = useState<{ reachable: boolean; models?: string[]; error?: string } | null>(null);
  const [testingConnection, setTestingConnection] = useState(false);
  const [toolSettings, setToolSettings] = useState(TOOL_SETTINGS_DEFAULT);
  const [savingToolSettings, setSavingToolSettings] = useState(false);
  const [toolSettingsMsg, setToolSettingsMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [ssoSettings, setSsoSettings] = useState({
    google_enabled: false,
    google_client_id: '',
    google_client_secret: '',
    google_client_secret_configured: false,
    microsoft_enabled: false,
    microsoft_client_id: '',
    microsoft_client_secret: '',
    microsoft_client_secret_configured: false,
    microsoft_tenant_id: 'common',
    sso_allowed_domains: '',
    sso_auto_provision: false,
  });
  const [savingSsoSettings, setSavingSsoSettings] = useState(false);
  const [ssoMsg, setSsoMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [notificationDelivery, setNotificationDelivery] = useState({
    enabled: false,
    provider: 'disabled' as 'disabled' | 'microsoft_graph' | 'microsoft_smtp',
    sender_email: '',
    reply_to_email: '',
    graph_tenant_id: 'common',
    graph_client_id: '',
    graph_client_secret: '',
    graph_client_secret_configured: false,
    smtp_host: '',
    smtp_port: 587,
    smtp_username: '',
    smtp_password: '',
    smtp_password_configured: false,
    smtp_use_starttls: true,
    smtp_use_ssl: false,
  });
  const [savingNotificationDelivery, setSavingNotificationDelivery] = useState(false);
  const [notificationDeliveryMsg, setNotificationDeliveryMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [testNotificationEmail, setTestNotificationEmail] = useState('');
  const [testingNotificationDelivery, setTestingNotificationDelivery] = useState(false);
  // Prompt templates state
  const [promptTemplates, setPromptTemplates] = useState<any[]>([]);
  const [editingPromptId, setEditingPromptId] = useState<string | null>(null);
  const [editingPromptText, setEditingPromptText] = useState('');
  const [savingPromptId, setSavingPromptId] = useState<string | null>(null);
  const [promptMsg, setPromptMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  // Plugins state
  const [plugins, setPlugins] = useState<any[]>([]);
  const [reloadingPlugins, setReloadingPlugins] = useState(false);
  const [pluginsMsg, setPluginsMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [pluginLogs, setPluginLogs] = useState<{ id: string; logs: string[] } | null>(null);
  // Builtin plugin marketplace state
  const [builtinPlugins, setBuiltinPlugins] = useState<any[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [configModal, setConfigModal] = useState<any | null>(null);
  const [configForm, setConfigForm] = useState<Record<string, string>>({});
  const [configEnabled, setConfigEnabled] = useState(false);
  const [savingPlugin, setSavingPlugin] = useState(false);
  const [testingPlugin, setTestingPlugin] = useState(false);
  const [pluginTestResult, setPluginTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  // Per-tool AI chat allowlist: one row per discovered tool, grouped by server. A row with no explicit choice follows its
  // server's switch above; overrides holds only the EXPLICIT per-tool choices (not every tool's resolved state).
  const [aiToolCatalog, setAiToolCatalog] = useState<Array<{ server: string; server_enabled: boolean; tools: Array<{ name: string; description: string; offensive: boolean; override: boolean | null; effective: boolean }> }>>([]);
  const [toolOverrides, setToolOverrides] = useState<Record<string, boolean>>({});
  const [loadingAiTools, setLoadingAiTools] = useState(false);

  const loadAiToolCatalog = async () => {
    setLoadingAiTools(true);
    try {
      const res = await settingsApi.getAiChatToolCatalog();
      const servers = res.data?.servers || [];
      setAiToolCatalog(servers);
      const overrides: Record<string, boolean> = {};
      for (const s of servers) for (const tool of s.tools) if (tool.override !== null && tool.override !== undefined) overrides[`${s.server}.${tool.name}`] = tool.override;
      setToolOverrides(overrides);
    } catch { /* the per-server switches above still work without this */ }
    finally { setLoadingAiTools(false); }
  };

  const setToolOverride = (server: string, tool: string, value: boolean | null) => {
    const key = `${server}.${tool}`;
    setToolOverrides((prev) => {
      const next = { ...prev };
      if (value === null) delete next[key]; else next[key] = value;
      return next;
    });
  };

  const allToolKeys = TOOL_CATEGORIES.flatMap((group) => group.items.map((item) => item.key));
  const enabledToolCount = allToolKeys.reduce((count, key) => {
    return count + (((toolSettings as any)[key] ?? false) ? 1 : 0);
  }, 0);

  const load = async () => {
    setLoading(true);
    try {
      const [statsRes, usersRes, llmRes, logsRes, settingsRes, ssoRes, notifDeliveryRes, promptTemplatesRes] = await Promise.all([
        adminApi.dashboard(),
        adminApi.users(),
        adminApi.llmConfigs(),
        adminApi.auditLogs(),
        fetch(`${API_BASE}/api/v1/admin/settings/remote-ollama`, {
          credentials: 'include',
        }).then(r => r.json()).catch(() => ({ url: '', model: '' })),
        adminApi.getSsoSettings().catch(() => null),
        adminApi.getNotificationDeliverySettings().catch(() => null),
        adminApi.promptTemplates().catch(() => null),
      ]);
      loadAiToolCatalog();
      setStats(statsRes.data);
      setUsers(usersRes.data.users || []);
      setLlmConfigs(llmRes.data || []);
      setAuditLogs(logsRes.data.logs || []);
      setRemoteOllamaUrl(settingsRes.url || '');
      setRemoteOllamaModel(settingsRes.model || '');
      if (ssoRes?.data) {
        setSsoSettings((prev) => ({
          ...prev,
          ...ssoRes.data,
          google_client_secret: '',
          microsoft_client_secret: '',
        }));
      }
      if (notifDeliveryRes?.data) {
        setNotificationDelivery((prev) => ({
          ...prev,
          ...notifDeliveryRes.data,
          provider: (notifDeliveryRes.data.provider || 'disabled') as 'disabled' | 'microsoft_graph' | 'microsoft_smtp',
          graph_client_secret: '',
          smtp_password: '',
        }));
      }
      if (promptTemplatesRes?.data) {
        setPromptTemplates(Array.isArray(promptTemplatesRes.data) ? promptTemplatesRes.data : []);
      }
      const toolRes = await settingsApi.getToolSettings().catch(() => null);
      if (toolRes?.data) {
        setToolSettings({ ...TOOL_SETTINGS_DEFAULT, ...toolRes.data });
      }
    } catch (err) {
      console.error('Failed to load admin data:', err);
    } finally { setLoading(false); }
  };

  const loadModelsForProvider = async (provider: string, remoteUrlOverride?: string) => {
    if (provider !== 'ollama_remote') {
      setAvailableModels([]);
      return;
    }

    setLoadingModels(true);
    try {
      const remoteUrl = (remoteUrlOverride ?? llmForm.api_url ?? remoteOllamaUrl ?? '').trim();
      const params: { provider: string; configured_only: boolean; remote_url?: string } = {
        provider,
        configured_only: false,
      };
      if (remoteUrl) params.remote_url = remoteUrl;

      const res = await llmApi.models(params);
      const data = res.data;
      const models = data.ollama_remote_models?.map((m: any) => m.name) || [];
      setAvailableModels(models);
      if (models.length > 0 && !llmForm.model_name) {
        setLlmForm(f => ({ ...f, model_name: models[0] }));
      }
    } catch (err) {
      console.error('Failed to load models:', err);
      setAvailableModels([]);
    } finally {
      setLoadingModels(false);
    }
  };

  // Live-probe a non-Ollama provider's real model list using the API key currently typed in the modal. Nothing is
  // saved by this call — it only tests the key and returns what the provider's own API reports right now.
  const fetchApiModels = async () => {
    const apiKey = (llmForm.api_key || '').trim();
    if (!apiKey) {
      setApiModelsError('Enter an API key first, then click Fetch Models.');
      return;
    }
    setFetchingApiModels(true);
    setApiModelsError(null);
    try {
      const res = await adminApi.fetchLlmModels({
        provider: llmForm.provider,
        api_key: apiKey,
        api_url: llmForm.api_url || undefined,
      });
      if (res.data.reachable) {
        setApiModels(res.data.models);
        if (res.data.models.length > 0 && !llmForm.model_name) {
          setLlmForm((f) => ({ ...f, model_name: res.data.models[0].id }));
        }
        if (res.data.models.length === 0) {
          setApiModelsError('Connected, but the provider returned no models.');
        }
      } else {
        setApiModels([]);
        setApiModelsError(res.data.error || 'Could not fetch models.');
      }
    } catch (err: any) {
      setApiModels([]);
      setApiModelsError(err?.response?.data?.detail || err?.message || 'Could not fetch models.');
    } finally {
      setFetchingApiModels(false);
    }
  };

  useEffect(() => { load(); }, []);

  useEffect(() => { if (tab === 'plugins') { loadPlugins(); loadBuiltinPlugins(); } }, [tab]);

  const toggleUser = async (id: string, is_active: boolean) => {
    try {
      await adminApi.updateUser(id, { is_active });
      load();
    } catch (err) {
      console.error('Failed to update user:', err);
    }
  };

  const deleteUser = async (id: string) => {
    if (!(await askConfirm('Permanently delete this user?'))) return;
    try {
      await adminApi.deleteUser(id);
      load();
    } catch (err) {
      console.error('Failed to delete user:', err);
    }
  };

  const addLlm = async () => {
    try {
      await adminApi.createLlmConfig(llmForm);
      setShowAddLlm(false);
      setAvailableModels([]);
      setApiModels([]); setApiModelsError(null);
      setLlmForm({ name: '', provider: 'ollama_remote', model_name: '', api_url: '', api_key: '', is_default: false });
      notify('LLM provider added', 'success');
      load();
    } catch (err: any) {
      // Previously this only logged to the browser console — the modal would just sit there (or the user would retry
      // and assume nothing happened), with no visible reason why. Surface the real error so a rejected field, a
      // permissions issue, or a network failure is actually visible.
      const detail = err?.response?.data?.detail || err?.message || 'Unknown error';
      console.error('Failed to create LLM config:', err);
      notify(`Failed to add LLM provider: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`, 'error');
    }
  };

  const deleteLlm = async (id: string) => {
    try {
      await adminApi.deleteLlmConfig(id);
      load();
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || 'Unknown error';
      console.error('Failed to delete LLM config:', err);
      notify(`Failed to delete LLM provider: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`, 'error');
    }
  };

  const makeLlmDefault = async (id: string) => {
    try {
      await adminApi.setDefaultLlmConfig(id);
      notify('Platform default updated', 'success');
      load();
    } catch (err: any) {
      const detail = err?.response?.data?.detail || err?.message || 'Unknown error';
      console.error('Failed to set default LLM config:', err);
      notify(`Failed to set platform default: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`, 'error');
    }
  };

  const saveRemoteOllamaSettings = async () => {
    if (!remoteOllamaUrl.trim()) {
      setSettingsMsg({ type: 'error', text: 'Please enter a remote Ollama URL' });
      return;
    }

    setSavingSettings(true);
    setSettingsMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/admin/settings/remote-ollama`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          url: remoteOllamaUrl,
          model: remoteOllamaModel || undefined,
        }),
      });

      if (!res.ok) {
        const error = await res.json();
        setSettingsMsg({ type: 'error', text: `Failed to save: ${error.detail || 'Unknown error'}` });
        return;
      }

      setSettingsMsg({ type: 'success', text: 'Remote Ollama settings saved successfully!' });
      load();
    } catch (err) {
      console.error('Failed to save settings:', err);
      setSettingsMsg({ type: 'error', text: 'Network error — could not save settings' });
    } finally {
      setSavingSettings(false);
    }
  };

  const testRemoteOllamaConnection = async () => {
    setTestingConnection(true);
    setTestResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/admin/settings/remote-ollama/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ url: remoteOllamaUrl.trim() || null }),
      });
      const data = await res.json();
      if (!res.ok) {
        setTestResult({ reachable: false, error: data.detail || 'Request failed' });
      } else {
        setTestResult(data);
      }
    } catch (err: any) {
      setTestResult({ reachable: false, error: err.message || 'Network error' });
    } finally {
      setTestingConnection(false);
    }
  };

  const saveToolPolicy = async () => {
    setSavingToolSettings(true);
    setToolSettingsMsg(null);
    try {
      const res = await settingsApi.saveToolSettings({ ...toolSettings, tool_overrides: toolOverrides });
      const warnings: string[] = res.data?.warnings || [];
      setToolSettingsMsg(warnings.length
        ? { type: 'error', text: `Saved, but ${warnings.length} tool choice${warnings.length === 1 ? ' was' : 's were'} rejected: ${warnings.join('; ')}` }
        : { type: 'success', text: 'Global Tools & MCP policy saved successfully.' });
      await load();
    } catch (err: any) {
      setToolSettingsMsg({ type: 'error', text: err?.response?.data?.detail || 'Failed to save tool policy.' });
    } finally {
      setSavingToolSettings(false);
    }
  };

  const saveSsoSettings = async () => {
    setSavingSsoSettings(true);
    setSsoMsg(null);
    try {
      const payload = {
        google_enabled: ssoSettings.google_enabled,
        google_client_id: ssoSettings.google_client_id.trim(),
        google_client_secret: ssoSettings.google_client_secret.trim() || undefined,
        microsoft_enabled: ssoSettings.microsoft_enabled,
        microsoft_client_id: ssoSettings.microsoft_client_id.trim(),
        microsoft_client_secret: ssoSettings.microsoft_client_secret.trim() || undefined,
        microsoft_tenant_id: ssoSettings.microsoft_tenant_id.trim() || 'common',
        sso_allowed_domains: ssoSettings.sso_allowed_domains.trim(),
        sso_auto_provision: ssoSettings.sso_auto_provision,
      };
      const res = await adminApi.saveSsoSettings(payload);
      setSsoSettings((prev) => ({
        ...prev,
        ...res.data,
        google_client_secret: '',
        microsoft_client_secret: '',
      }));
      setSsoMsg({ type: 'success', text: 'SSO settings saved securely. Secrets are encrypted at rest.' });
    } catch (err: any) {
      setSsoMsg({ type: 'error', text: err?.response?.data?.detail || 'Failed to save SSO settings.' });
    } finally {
      setSavingSsoSettings(false);
    }
  };

  const saveNotificationDeliverySettings = async () => {
    setSavingNotificationDelivery(true);
    setNotificationDeliveryMsg(null);
    try {
      const payload = {
        enabled: notificationDelivery.enabled,
        provider: notificationDelivery.provider,
        sender_email: notificationDelivery.sender_email.trim(),
        reply_to_email: notificationDelivery.reply_to_email.trim() || undefined,
        graph_tenant_id: notificationDelivery.graph_tenant_id.trim() || 'common',
        graph_client_id: notificationDelivery.graph_client_id.trim() || undefined,
        graph_client_secret: notificationDelivery.graph_client_secret.trim() || undefined,
        smtp_host: notificationDelivery.smtp_host.trim() || undefined,
        smtp_port: notificationDelivery.smtp_port,
        smtp_username: notificationDelivery.smtp_username.trim() || undefined,
        smtp_password: notificationDelivery.smtp_password.trim() || undefined,
        smtp_use_starttls: notificationDelivery.smtp_use_starttls,
        smtp_use_ssl: notificationDelivery.smtp_use_ssl,
      };
      const res = await adminApi.saveNotificationDeliverySettings(payload);
      setNotificationDelivery((prev) => ({
        ...prev,
        ...res.data,
        provider: (res.data.provider || 'disabled') as 'disabled' | 'microsoft_graph' | 'microsoft_smtp',
        graph_client_secret: '',
        smtp_password: '',
      }));
      setNotificationDeliveryMsg({ type: 'success', text: 'Notification delivery settings saved securely.' });
    } catch (err: any) {
      setNotificationDeliveryMsg({ type: 'error', text: err?.response?.data?.detail || 'Failed to save notification delivery settings.' });
    } finally {
      setSavingNotificationDelivery(false);
    }
  };

  const sendTestNotificationDelivery = async () => {
    setTestingNotificationDelivery(true);
    setNotificationDeliveryMsg(null);
    try {
      const payload = {
        recipient_email: testNotificationEmail.trim() || undefined,
      };
      const res = await adminApi.testNotificationDeliverySettings(payload);
      const data = res.data || {};
      setNotificationDeliveryMsg({
        type: 'success',
        text: `Test sent to ${data.recipient_email || 'configured recipient'} via ${data.provider || 'provider'}.`,
      });
    } catch (err: any) {
      setNotificationDeliveryMsg({
        type: 'error',
        text: err?.response?.data?.detail || 'Failed to dispatch test notification.',
      });
    } finally {
      setTestingNotificationDelivery(false);
    }
  };

  const setAllToolsEnabled = (enabled: boolean) => {
    setToolSettings((current) => {
      const next: any = { ...current };
      for (const key of allToolKeys) next[key] = enabled;
      return next;
    });
  };

  const togglePromptActive = async (tpl: any) => {
    try {
      await adminApi.updatePromptTemplate(tpl.id, { is_active: !tpl.is_active });
      setPromptTemplates((prev) => prev.map((t) => t.id === tpl.id ? { ...t, is_active: !t.is_active } : t));
    } catch (err) {
      console.error('Failed to toggle prompt template:', err);
    }
  };

  const setPromptAsDefault = async (tpl: any) => {
    try {
      await adminApi.updatePromptTemplate(tpl.id, { is_default: true });
      setPromptTemplates((prev) => prev.map((t) =>
        t.scan_type === tpl.scan_type ? { ...t, is_default: t.id === tpl.id } : t
      ));
    } catch (err) {
      console.error('Failed to set prompt as default:', err);
    }
  };

  const savePromptEdit = async (id: string) => {
    setSavingPromptId(id);
    setPromptMsg(null);
    try {
      await adminApi.updatePromptTemplate(id, { system_prompt: editingPromptText });
      setPromptTemplates((prev) => prev.map((t) => t.id === id ? { ...t, system_prompt: editingPromptText } : t));
      setEditingPromptId(null);
      setPromptMsg({ type: 'success', text: 'Prompt template saved.' });
    } catch (err: any) {
      setPromptMsg({ type: 'error', text: err?.response?.data?.detail || 'Failed to save prompt template.' });
    } finally {
      setSavingPromptId(null);
    }
  };

  const deletePromptTemplate = async (id: string) => {
    if (!(await askConfirm('Delete this prompt template?'))) return;
    setPromptMsg(null);
    try {
      await adminApi.deletePromptTemplate(id);
      setPromptTemplates((prev) => prev.filter((t) => t.id !== id));
      setPromptMsg({ type: 'success', text: 'Prompt template deleted.' });
    } catch (err: any) {
      setPromptMsg({ type: 'error', text: err?.response?.data?.detail || 'Cannot delete built-in template.' });
    }
  };

  const loadPlugins = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/admin/plugins`, { credentials: 'include' });
      const data = await res.json();
      setPlugins(Array.isArray(data) ? data : (data.plugins || []));
    } catch { /* silent */ }
  };

  const loadBuiltinPlugins = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/admin/plugins/builtin`, { credentials: 'include' });
      const data = await res.json();
      setBuiltinPlugins(data.plugins || []);
    } catch { /* silent */ }
  };

  const openConfigModal = (plugin: any) => {
    setConfigModal(plugin);
    setConfigEnabled(plugin.enabled ?? false);
    // Pre-fill non-sensitive fields from config_preview
    const preview = plugin.config_preview || {};
    const initial: Record<string, string> = {};
    (plugin.fields || []).forEach((f: any) => {
      initial[f.key] = f.sensitive ? '' : (preview[f.key] ?? '');
    });
    setConfigForm(initial);
    setPluginTestResult(null);
  };

  const savePluginConfig = async () => {
    if (!configModal) return;
    setSavingPlugin(true);
    setPluginsMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/admin/plugins/builtin/${encodeURIComponent(configModal.id)}/configure`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: configEnabled, config: configForm }),
      });
      if (res.ok) {
        setPluginsMsg({ type: 'success', text: `${configModal.name} configuration saved.` });
        setConfigModal(null);
        await loadBuiltinPlugins();
      } else {
        const err = await res.json().catch(() => ({}));
        setPluginsMsg({ type: 'error', text: err.detail || 'Failed to save configuration' });
      }
    } catch { setPluginsMsg({ type: 'error', text: 'Network error' }); }
    finally { setSavingPlugin(false); }
  };

  const testPluginConnection = async () => {
    if (!configModal) return;
    setTestingPlugin(true);
    setPluginTestResult(null);
    try {
      // Save config first (silently) so test uses latest values
      await fetch(`${API_BASE}/api/v1/admin/plugins/builtin/${encodeURIComponent(configModal.id)}/configure`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: configEnabled, config: configForm }),
      });
      const res = await fetch(`${API_BASE}/api/v1/admin/plugins/builtin/${encodeURIComponent(configModal.id)}/test`, {
        method: 'POST', credentials: 'include',
      });
      const data = await res.json();
      setPluginTestResult(data);
      await loadBuiltinPlugins();
    } catch { setPluginTestResult({ ok: false, message: 'Network error' }); }
    finally { setTestingPlugin(false); }
  };

  const toggleBuiltinPlugin = async (pluginId: string, enabled: boolean) => {
    try {
      await fetch(`${API_BASE}/api/v1/admin/plugins/builtin/${encodeURIComponent(pluginId)}/toggle`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      await loadBuiltinPlugins();
    } catch { /* silent */ }
  };

  const reloadPlugins = async () => {
    setReloadingPlugins(true);
    setPluginsMsg(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/admin/plugins/reload`, { method: 'POST', credentials: 'include' });
      const data = await res.json();
      setPluginsMsg({ type: 'success', text: `Plugins reloaded. Loaded: ${data.loaded_count ?? 0}` });
      await loadPlugins();
    } catch (err: any) {
      setPluginsMsg({ type: 'error', text: 'Failed to reload plugins' });
    } finally {
      setReloadingPlugins(false);
    }
  };

  const fetchPluginLogs = async (pluginId: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/admin/plugins/${encodeURIComponent(pluginId)}/logs`, { credentials: 'include' });
      const data = await res.json();
      setPluginLogs({ id: pluginId, logs: Array.isArray(data.logs) ? data.logs : [] });
    } catch { setPluginLogs({ id: pluginId, logs: ['Failed to fetch logs'] }); }
  };

  return (
    <SettingsShell
      title="Administration" badge="Admins only" subtitle="Manage people, platform policy and governance for your organization."
      groups={ADMIN_GROUPS} active={section}
      callout={{ title: 'Your own settings', text: 'Profile, security and API tokens are in Settings.', href: '/settings', cta: 'Open Settings' }}
    >
      {/* Users Tab */}
      {tab === 'users' && <UsersPanel />}

      {/* Audit Logs Tab */}
      {tab === 'logs' && (
        <>
        <SectionHead title="Audit log" desc="Who did what, and when. Sign-ins, role changes, resets and deletions are recorded here."
          actions={<button onClick={load} className="btn btn-ghost btn-sm"><RefreshCw size={14} /> Refresh</button>} />
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="data-table">
            <thead><tr><th>Action</th><th>Resource</th><th>User ID</th><th>IP Address</th><th>Timestamp</th></tr></thead>
            <tbody>
              {auditLogs.length === 0 ? (
                <tr><td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>No audit logs yet.</td></tr>
              ) : auditLogs.map((l: any) => (
                <tr key={l.id}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--cyan)' }}>{l.action}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{l.resource_type}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>{l.user_id?.slice(0, 8)}...</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>{l.ip_address || '—'}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{new Date(l.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </>
      )}

      {/* Prompt Templates Tab */}
      {tab === 'prompt_templates' && (
        <div style={{ display: 'grid', gap: '1rem' }}>
          <div className="card" style={{ padding: '1.25rem 1.5rem' }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.35rem' }}>AI Prompt Templates</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
              Offensive methodology prompts prepended to the base system prompt during scan analysis.
              Built-in templates (🔒) cannot be deleted. The active default for each scan type is used automatically.
            </p>
          </div>
          {promptMsg && (
            <div style={{
              padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)', fontSize: '0.875rem',
              background: promptMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 8%, transparent)' : 'color-mix(in srgb, var(--red) 8%, transparent)',
              color: promptMsg.type === 'success' ? 'var(--green)' : 'var(--red)',
              border: `1px solid ${promptMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 19%, transparent)' : 'color-mix(in srgb, var(--red) 19%, transparent)'}`,
            }}>{promptMsg.text}</div>
          )}
          {promptTemplates.length === 0 ? (
            <div className="card" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>No prompt templates found.</div>
          ) : promptTemplates.map((tpl) => (
            <div key={tpl.id} className="card" style={{ padding: '1.25rem 1.5rem', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: 200 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.35rem' }}>
                    <span style={{ fontWeight: 700, fontSize: '1rem' }}>{tpl.name}</span>
                    {tpl.is_builtin && <span title="Built-in — cannot be deleted" style={{ fontSize: '0.75rem' }}>🔒</span>}
                    {tpl.scan_type ? (
                      <span style={{
                        fontSize: '0.6875rem', padding: '2px 8px', borderRadius: 99, fontWeight: 600,
                        background: 'color-mix(in srgb, var(--cyan) 8%, transparent)', color: 'var(--cyan)', border: '1px solid color-mix(in srgb, var(--cyan) 19%, transparent)',
                      }}>{tpl.scan_type}</span>
                    ) : (
                      <span style={{
                        fontSize: '0.6875rem', padding: '2px 8px', borderRadius: 99, fontWeight: 600,
                        background: 'color-mix(in srgb, var(--purple) 8%, transparent)', color: 'var(--purple)', border: '1px solid color-mix(in srgb, var(--purple) 19%, transparent)',
                      }}>all types</span>
                    )}
                    {tpl.is_default && (
                      <span style={{
                        fontSize: '0.6875rem', padding: '2px 8px', borderRadius: 99, fontWeight: 600,
                        background: 'color-mix(in srgb, var(--green) 8%, transparent)', color: 'var(--green)', border: '1px solid color-mix(in srgb, var(--green) 19%, transparent)',
                      }}>default</span>
                    )}
                    <span style={{
                      fontSize: '0.6875rem', padding: '2px 8px', borderRadius: 99, fontWeight: 600,
                      background: tpl.is_active ? 'color-mix(in srgb, var(--green) 8%, transparent)' : 'color-mix(in srgb, var(--red) 8%, transparent)',
                      color: tpl.is_active ? 'var(--green)' : 'var(--red)',
                      border: `1px solid ${tpl.is_active ? 'color-mix(in srgb, var(--green) 19%, transparent)' : 'color-mix(in srgb, var(--red) 19%, transparent)'}`,
                    }}>{tpl.is_active ? 'active' : 'inactive'}</span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '0.4rem', flexShrink: 0, flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-ghost"
                    style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem' }}
                    onClick={() => togglePromptActive(tpl)}
                  >{tpl.is_active ? 'Disable' : 'Enable'}</button>
                  {!tpl.is_default && (
                    <button
                      className="btn btn-ghost"
                      style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem' }}
                      onClick={() => setPromptAsDefault(tpl)}
                    >Set Default</button>
                  )}
                  <button
                    className="btn btn-ghost"
                    style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem' }}
                    onClick={() => { setEditingPromptId(tpl.id); setEditingPromptText(tpl.system_prompt); }}
                  >Edit</button>
                  <button
                    className="btn btn-danger"
                    style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', opacity: tpl.is_builtin ? 0.35 : 1 }}
                    disabled={tpl.is_builtin}
                    title={tpl.is_builtin ? 'Built-in templates cannot be deleted' : 'Delete'}
                    onClick={() => deletePromptTemplate(tpl.id)}
                  ><Trash2 size={12} /></button>
                </div>
              </div>
              {editingPromptId === tpl.id && (
                <div style={{ marginTop: '1rem' }}>
                  <textarea
                    value={editingPromptText}
                    onChange={(e) => setEditingPromptText(e.target.value)}
                    rows={12}
                    style={{
                      width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                      borderRadius: 'var(--radius-sm)', padding: '0.75rem', fontFamily: 'var(--font-mono)',
                      fontSize: '0.75rem', color: 'var(--text)', resize: 'vertical',
                    }}
                  />
                  <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
                    <button
                      className="btn btn-primary"
                      style={{ fontSize: '0.8125rem' }}
                      disabled={savingPromptId === tpl.id}
                      onClick={() => savePromptEdit(tpl.id)}
                    >{savingPromptId === tpl.id ? 'Saving...' : 'Save'}</button>
                    <button
                      className="btn btn-ghost"
                      style={{ fontSize: '0.8125rem' }}
                      onClick={() => setEditingPromptId(null)}
                    >Cancel</button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Plugins Tab */}
      {tab === 'plugins' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>

          {/* Header */}
          <div className="card" style={{ padding: '1.25rem 1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div>
              <h2 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.25rem' }}>Plugin Marketplace</h2>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                12 pre-built enterprise integrations. Configure via UI — no script uploads required.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <button className="btn btn-ghost" onClick={loadBuiltinPlugins} style={{ fontSize: '0.8125rem' }}>↺ Refresh</button>
              <button className="btn btn-ghost" onClick={reloadPlugins} disabled={reloadingPlugins} style={{ fontSize: '0.8125rem' }}>
                {reloadingPlugins ? 'Reloading...' : 'Reload Custom Plugins'}
              </button>
            </div>
          </div>

          {pluginsMsg && (
            <div style={{
              padding: '0.625rem 0.875rem', borderRadius: 'var(--radius-md)', fontSize: '0.8125rem', fontWeight: 600,
              background: pluginsMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 7%, transparent)' : 'color-mix(in srgb, var(--red) 7%, transparent)',
              border: `1px solid ${pluginsMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 24%, transparent)' : 'color-mix(in srgb, var(--red) 24%, transparent)'}`,
              color: pluginsMsg.type === 'success' ? 'var(--green)' : 'var(--red)',
            }}>{pluginsMsg.text}</div>
          )}

          {/* Category filter tabs */}
          {(() => {
            const cats = ['All', ...Array.from(new Set(builtinPlugins.map((p: any) => p.category).filter(Boolean)))];
            return (
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                {cats.map(cat => (
                  <button key={cat} onClick={() => setCategoryFilter(cat)} style={{
                    padding: '0.3rem 0.85rem', borderRadius: 99, fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer',
                    border: `1px solid ${categoryFilter === cat ? 'var(--accent)' : 'var(--border)'}`,
                    background: categoryFilter === cat ? 'var(--accent)' : 'transparent',
                    color: categoryFilter === cat ? '#fff' : 'var(--text-muted)',
                    transition: 'all 0.15s',
                  }}>{cat}</button>
                ))}
              </div>
            );
          })()}

          {/* Plugin Cards Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(310px, 1fr))', gap: '1rem' }}>
            {builtinPlugins
              .filter((p: any) => categoryFilter === 'All' || p.category === categoryFilter)
              .map((plugin: any) => (
                <div key={plugin.id} className="card" style={{
                  padding: '1.1rem 1.25rem',
                  border: `1px solid ${plugin.enabled ? 'color-mix(in srgb, var(--green) 19%, transparent)' : 'var(--border)'}`,
                  display: 'flex', flexDirection: 'column', gap: '0.65rem',
                }}>
                  {/* Card header */}
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem' }}>
                    <span style={{ fontSize: '1.5rem', lineHeight: 1 }}>{plugin.icon || '🔌'}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.875rem' }}>{plugin.name}</span>
                        <span style={{
                          fontSize: '0.6875rem', fontWeight: 700, padding: '1px 7px', borderRadius: 99,
                          background: 'color-mix(in srgb, var(--indigo) 8%, transparent)', color: 'var(--indigo)', border: '1px solid color-mix(in srgb, var(--indigo) 19%, transparent)',
                        }}>{plugin.category}</span>
                        {plugin.enabled && (
                          <span style={{
                            fontSize: '0.6875rem', fontWeight: 700, padding: '1px 7px', borderRadius: 99,
                            background: 'color-mix(in srgb, var(--green) 8%, transparent)', color: 'var(--green)', border: '1px solid color-mix(in srgb, var(--green) 19%, transparent)',
                          }}>● Active</span>
                        )}
                      </div>
                      <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.2rem', lineHeight: 1.4 }}>
                        {plugin.description}
                      </p>
                    </div>
                  </div>

                  {/* Stats row */}
                  {(plugin.trigger_count > 0 || plugin.last_triggered_at) && (
                    <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {plugin.trigger_count > 0 && <span>🔁 {plugin.trigger_count} triggers</span>}
                      {plugin.last_triggered_at && <span>🕒 {new Date(plugin.last_triggered_at).toLocaleDateString()}</span>}
                    </div>
                  )}

                  {/* Hooks badges */}
                  <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                    {(plugin.hooks || []).map((h: string) => (
                      <span key={h} style={{
                        fontSize: '0.6875rem', padding: '1px 6px', borderRadius: 'var(--radius-sm)',
                        background: 'var(--bg-secondary)', color: 'var(--text-muted)',
                        border: '1px solid var(--border)', fontFamily: 'monospace',
                      }}>{h}</span>
                    ))}
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: '0.5rem', marginTop: 'auto', paddingTop: '0.35rem', borderTop: '1px solid var(--border)' }}>
                    {/* Toggle */}
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', fontSize: '0.75rem', color: plugin.enabled ? 'var(--green)' : 'var(--text-muted)' }}>
                      <input type="checkbox" checked={plugin.enabled ?? false}
                        onChange={e => toggleBuiltinPlugin(plugin.id, e.target.checked)}
                        style={{ accentColor: 'var(--green)' }} />
                      {plugin.enabled ? 'Enabled' : 'Disabled'}
                    </label>
                    <div style={{ flex: 1 }} />
                    <button className="btn btn-primary" style={{ fontSize: '0.75rem', padding: '0.2rem 0.7rem' }}
                      onClick={() => openConfigModal(plugin)}>
                      {plugin.configured ? '⚙ Edit Config' : '⚙ Configure'}
                    </button>
                  </div>
                </div>
              ))}
            {builtinPlugins.length === 0 && (
              <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: '3rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                <Loader2 size={20} className="animate-spin" style={{ margin: '0 auto 0.75rem' }} />
                Loading plugins...
              </div>
            )}
          </div>

          {/* Custom (file-based) plugins section */}
          {plugins.length > 0 && (
            <div className="card" style={{ padding: '1rem' }}>
              <div style={{ fontWeight: 700, marginBottom: '0.75rem', fontSize: '0.875rem' }}>Custom File-based Plugins ({plugins.length})</div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left' }}>Plugin</th>
                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left' }}>Version</th>
                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'left' }}>Status</th>
                    <th style={{ padding: '0.4rem 0.6rem', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {plugins.map((p: any) => (
                    <tr key={p.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '0.55rem 0.6rem' }}>
                        <div style={{ fontWeight: 600 }}>{p.name || p.id}</div>
                        {p.description && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 1 }}>{p.description}</div>}
                      </td>
                      <td style={{ padding: '0.55rem 0.6rem', color: 'var(--text-muted)' }}>{p.version || '—'}</td>
                      <td style={{ padding: '0.55rem 0.6rem' }}>
                        <span style={{
                          fontSize: '0.6875rem', fontWeight: 700, padding: '1px 7px', borderRadius: 99,
                          background: p.enabled !== false ? 'color-mix(in srgb, var(--green) 8%, transparent)' : 'color-mix(in srgb, var(--red) 8%, transparent)',
                          color: p.enabled !== false ? 'var(--green)' : 'var(--red)',
                          border: `1px solid ${p.enabled !== false ? 'color-mix(in srgb, var(--green) 19%, transparent)' : 'color-mix(in srgb, var(--red) 19%, transparent)'}`,
                        }}>{p.enabled !== false ? 'enabled' : 'disabled'}</span>
                      </td>
                      <td style={{ padding: '0.55rem 0.6rem', textAlign: 'right' }}>
                        <button className="btn btn-ghost" style={{ fontSize: '0.75rem', padding: '0.18rem 0.5rem' }} onClick={() => fetchPluginLogs(p.id)}>
                          View Logs
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Plugin logs modal */}
          {pluginLogs && (
            <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.65)', zIndex: 9000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
              onClick={() => setPluginLogs(null)}>
              <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '1.5rem', width: '90%', maxWidth: 700, maxHeight: '70vh', overflow: 'auto' }}
                onClick={e => e.stopPropagation()}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <h3 style={{ fontWeight: 700 }}>Plugin Logs: {pluginLogs.id}</h3>
                  <button className="btn btn-ghost" onClick={() => setPluginLogs(null)}>Close</button>
                </div>
                <div className="terminal" style={{ whiteSpace: 'pre-wrap', maxHeight: '50vh', overflow: 'auto', fontSize: '0.75rem' }}>
                  {pluginLogs.logs.length > 0 ? pluginLogs.logs.join('\n') : 'No logs available.'}
                </div>
              </div>
            </div>
          )}

          {/* Plugin Config Modal */}
          {configModal && (
            <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 9100, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem' }}
              onClick={() => setConfigModal(null)}>
              <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '1.75rem', width: '100%', maxWidth: 560, maxHeight: '90vh', overflow: 'auto' }}
                onClick={e => e.stopPropagation()}>

                {/* Modal header */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
                  <span style={{ fontSize: '1.75rem' }}>{configModal.icon || '🔌'}</span>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '1rem' }}>{configModal.name}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{configModal.category} · {configModal.version || 'v1.0.0'}</div>
                  </div>
                  <div style={{ flex: 1 }} />
                  <button className="btn btn-ghost" onClick={() => setConfigModal(null)} style={{ fontSize: '1rem', padding: '0.1rem 0.5rem' }}>✕</button>
                </div>

                {/* Enable toggle */}
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.25rem', cursor: 'pointer', fontSize: '0.875rem', fontWeight: 600 }}>
                  <input type="checkbox" checked={configEnabled} onChange={e => setConfigEnabled(e.target.checked)} style={{ accentColor: 'var(--green)', width: 16, height: 16 }} />
                  Enable this plugin
                </label>

                {/* Config fields */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', marginBottom: '1.25rem' }}>
                  {(configModal.fields || []).map((field: any) => (
                    <div key={field.key}>
                      <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '0.3rem' }}>
                        {field.label}{field.required && <span style={{ color: 'var(--red)' }}> *</span>}
                        {field.sensitive && <span style={{ color: 'var(--orange)', marginLeft: '0.35rem', fontSize: '0.6875rem' }}>🔒 encrypted</span>}
                      </label>
                      {field.options ? (
                        <select
                          value={configForm[field.key] ?? ''}
                          onChange={e => setConfigForm(prev => ({ ...prev, [field.key]: e.target.value }))}
                          style={{ width: '100%', padding: '0.45rem 0.65rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: '0.8125rem' }}
                        >
                          <option value="">Select...</option>
                          {field.options.map((opt: string) => (
                            <option key={opt} value={opt}>{opt}</option>
                          ))}
                        </select>
                      ) : (
                        <input
                          type={field.sensitive ? 'password' : 'text'}
                          placeholder={field.sensitive && !configForm[field.key] && configModal.configured ? '(leave blank to keep existing)' : (field.placeholder || '')}
                          value={configForm[field.key] ?? ''}
                          onChange={e => setConfigForm(prev => ({ ...prev, [field.key]: e.target.value }))}
                          style={{ width: '100%', padding: '0.45rem 0.65rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--bg)', color: 'var(--text)', fontSize: '0.8125rem', boxSizing: 'border-box' }}
                          autoComplete={field.sensitive ? 'new-password' : undefined}
                        />
                      )}
                    </div>
                  ))}
                </div>

                {/* Test result */}
                {pluginTestResult && (
                  <div style={{
                    padding: '0.6rem 0.85rem', borderRadius: 'var(--radius-md)', marginBottom: '1rem', fontSize: '0.8125rem', fontWeight: 600,
                    background: pluginTestResult.ok ? 'color-mix(in srgb, var(--green) 6%, transparent)' : 'color-mix(in srgb, var(--red) 6%, transparent)',
                    border: `1px solid ${pluginTestResult.ok ? 'color-mix(in srgb, var(--green) 21%, transparent)' : 'color-mix(in srgb, var(--red) 21%, transparent)'}`,
                    color: pluginTestResult.ok ? 'var(--green)' : 'var(--red)',
                  }}>
                    {pluginTestResult.ok ? '✅' : '❌'} {pluginTestResult.message}
                  </div>
                )}

                {/* Action buttons */}
                <div style={{ display: 'flex', gap: '0.6rem', justifyContent: 'flex-end' }}>
                  <button className="btn btn-ghost" onClick={() => setConfigModal(null)} style={{ fontSize: '0.8125rem' }}>Cancel</button>
                  <button className="btn btn-ghost" onClick={testPluginConnection} disabled={testingPlugin} style={{ fontSize: '0.8125rem' }}>
                    {testingPlugin ? <><Loader2 size={12} className="animate-spin" /> Testing...</> : '🔌 Test Connection'}
                  </button>
                  <button className="btn btn-primary" onClick={savePluginConfig} disabled={savingPlugin} style={{ fontSize: '0.8125rem' }}>
                    {savingPlugin ? <><Loader2 size={12} className="animate-spin" /> Saving...</> : '💾 Save'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Settings Tab */}
      {tab === 'settings' && (
        <div style={{ display: 'grid', gap: '1rem' }}>
          <SectionHead title={SUB_HEAD[settingsSubtab].title} desc={SUB_HEAD[settingsSubtab].desc} />

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            {settingsSubtab === 'platform' && (
              <>
            <div className="card" style={{ padding: '1.5rem', border: '1px solid var(--border)' }}>
              <div style={{ marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem' }}>Remote Ollama Configuration</h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                  Define a managed remote endpoint so teams can select approved models directly.
                </p>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                    Remote Ollama URL
                  </label>
                  <input
                    type="text"
                    className="input"
                    placeholder="http://192.168.20.13:11434"
                    value={remoteOllamaUrl}
                    onChange={(e) => {
                      setRemoteOllamaUrl(e.target.value);
                      setTestResult(null);
                    }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                    Default Model
                  </label>
                  <input
                    type="text"
                    className="input"
                    placeholder="qwen3.5:4b"
                    value={remoteOllamaModel}
                    onChange={(e) => setRemoteOllamaModel(e.target.value)}
                  />
                </div>

                {settingsMsg && (
                  <div style={{
                    padding: '0.625rem 0.875rem',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '0.8125rem',
                    fontWeight: 600,
                    background: settingsMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 7%, transparent)' : 'color-mix(in srgb, var(--red) 7%, transparent)',
                    border: `1px solid ${settingsMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 24%, transparent)' : 'color-mix(in srgb, var(--red) 24%, transparent)'}`,
                    color: settingsMsg.type === 'success' ? 'var(--green)' : 'var(--red)',
                  }}>
                    {settingsMsg.type === 'success' ? 'SUCCESS: ' : 'ERROR: '}
                    {settingsMsg.text}
                  </div>
                )}

                {testResult && (
                  <div style={{
                    padding: '0.75rem',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '0.8125rem',
                    background: testResult.reachable ? 'color-mix(in srgb, var(--green) 7%, transparent)' : 'color-mix(in srgb, var(--red) 7%, transparent)',
                    border: `1px solid ${testResult.reachable ? 'color-mix(in srgb, var(--green) 24%, transparent)' : 'color-mix(in srgb, var(--red) 24%, transparent)'}`,
                  }}>
                    {testResult.reachable ? (
                      <>
                        <p style={{ color: 'var(--green)', fontWeight: 700, margin: '0 0 0.45rem 0' }}>
                          Endpoint reachable: {testResult.models?.length ?? 0} model{testResult.models?.length !== 1 ? 's' : ''} detected
                        </p>
                        {testResult.models && testResult.models.length > 0 && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem', maxHeight: '120px', overflowY: 'auto' }}>
                            {testResult.models.map((m: string) => (
                              <span key={m} style={{
                                fontSize: '0.6875rem',
                                padding: '0.2rem 0.5rem',
                                borderRadius: 999,
                                background: 'color-mix(in srgb, var(--green) 9%, transparent)',
                                border: '1px solid color-mix(in srgb, var(--green) 24%, transparent)',
                                color: 'var(--green)',
                                fontFamily: 'var(--font-mono)',
                              }}>
                                {m}
                              </span>
                            ))}
                          </div>
                        )}
                      </>
                    ) : (
                      <p style={{ color: 'var(--red)', fontWeight: 700, margin: 0 }}>
                        Connection failed: {testResult.error || 'Not reachable'}
                      </p>
                    )}
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.625rem', marginTop: '0.25rem' }}>
                  <button
                    onClick={testRemoteOllamaConnection}
                    disabled={testingConnection || !remoteOllamaUrl.trim()}
                    className="btn btn-ghost"
                    title="Test connectivity to remote URL"
                  >
                    {testingConnection ? (
                      <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Testing...</>
                    ) : (
                      'Test Connection'
                    )}
                  </button>
                  <button onClick={saveRemoteOllamaSettings} disabled={savingSettings} className="btn btn-primary">
                    {savingSettings ? (
                      <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Saving...</>
                    ) : (
                      'Save Endpoint'
                    )}
                  </button>
                </div>

                </div>
            </div>

            <div className="card" style={{ padding: '1.5rem', border: '1px solid var(--border)', gridColumn: 'span 2', minWidth: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
                    <div>
                      <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.25rem' }}>LLM Providers</h3>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        Connect any provider — OpenAI, Anthropic, OpenRouter, Grok, Mistral, or a profile pointed at your
                        Remote Ollama endpoint above — each with its own model and API key. These are the providers
                        people can choose from in AI chat and analysis.
                      </p>
                    </div>
                    <button onClick={() => {
                      setShowAddLlm(true);
                      setAvailableModels([]);
                      setApiModels([]); setApiModelsError(null);
                      setLlmForm({ name: '', provider: 'ollama_remote', model_name: '', api_url: '', api_key: '', is_default: false });
                    }} className="btn btn-primary">
                      <Plus size={15} /> Add LLM Provider
                    </button>
                  </div>

                  {llmConfigs.some((c: any) => c.is_default) ? (
                    <div style={{
                      display: 'flex', alignItems: 'center', gap: 8, marginBottom: '0.75rem',
                      padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-md)',
                      background: 'color-mix(in srgb, var(--green) 8%, transparent)',
                      border: '1px solid color-mix(in srgb, var(--green) 25%, transparent)',
                      fontSize: '0.75rem', color: 'var(--green)',
                    }}>
                      <strong>Platform default:</strong>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        the row marked "✓ Default" below is what the automatic post-scan AI analysis, and any feature
                        that doesn't ask you to pick a provider, will actually use.
                      </span>
                    </div>
                  ) : (
                    <div style={{
                      display: 'flex', alignItems: 'center', gap: 8, marginBottom: '0.75rem',
                      padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-md)',
                      background: 'color-mix(in srgb, var(--amber) 8%, transparent)',
                      border: '1px solid color-mix(in srgb, var(--amber) 25%, transparent)',
                      fontSize: '0.75rem', color: 'var(--amber)',
                    }}>
                      <strong>No platform default set:</strong>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        mark one provider below as default (or it falls back to Ollama's .env configuration) — this
                        is what runs when a feature doesn't ask you to choose, like the automatic post-scan analysis.
                      </span>
                    </div>
                  )}

                  <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', overflowX: 'auto' }}>
                    <table className="data-table" style={{ width: '100%', minWidth: 480 }}>
                      <thead><tr><th>Name</th><th>Provider</th><th>Model</th><th title="Which provider automatic/unattended features use">Platform Default</th><th>Actions</th></tr></thead>
                      <tbody>
                        {llmConfigs.map((c: any) => (
                          <tr key={c.id}>
                            <td style={{ fontWeight: 500 }}>{c.name}</td>
                            <td style={{ color: 'var(--cyan)', fontSize: '0.8125rem', fontWeight: 600 }}>{providerLabel(c.provider)}</td>
                            <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>{c.model_name}</td>
                            <td>{c.is_default && <span style={{ color: 'var(--green)', fontSize: '0.75rem', fontWeight: 600 }}>✓ Default</span>}</td>
                            <td style={{ display: 'flex', gap: 6 }}>
                              {!c.is_default && (
                                <button
                                  onClick={() => makeLlmDefault(c.id)}
                                  className="btn btn-ghost"
                                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                                  title="Make this the platform default — used by any feature that doesn't ask you to choose"
                                >
                                  Make Default
                                </button>
                              )}
                              <button onClick={() => deleteLlm(c.id)} className="btn btn-danger" style={{ padding: '0.25rem 0.5rem' }}>
                                <Trash2 size={13} />
                              </button>
                            </td>
                          </tr>
                        ))}
                        {llmConfigs.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-muted)' }}>No LLM configs. Add one above.</td></tr>}
                      </tbody>
                    </table>
                  </div>
                </div>

            {showAddLlm && (
              <div
                role="dialog"
                aria-modal="true"
                aria-labelledby="llm-modal-title"
                style={{
                  position: 'fixed',
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  background: 'rgba(0,0,0,0.75)',
                  backdropFilter: 'blur(4px)',
                  zIndex: 50,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  overflow: 'auto',
                }}
                onClick={(e) => {
                  if (e.target === e.currentTarget) {
                    setShowAddLlm(false);
                    setAvailableModels([]);
                    setApiModels([]); setApiModelsError(null);
                    setLlmForm({ name: '', provider: 'ollama_remote', model_name: '', api_url: '', api_key: '', is_default: false });
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Escape') {
                    setShowAddLlm(false);
                    setAvailableModels([]);
                    setApiModels([]); setApiModelsError(null);
                    setLlmForm({ name: '', provider: 'ollama_remote', model_name: '', api_url: '', api_key: '', is_default: false });
                  }
                }}
              >
                <div className="card" style={{ width: 480, padding: '2rem', maxHeight: '90vh', overflow: 'auto' }}>
                  <h2 id="llm-modal-title" style={{ fontWeight: 700, marginBottom: '1.5rem' }}>Add LLM Provider</h2>
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (llmForm.provider === 'ollama_remote' && !llmForm.model_name) {
                        notify('Please select a model from the dropdown', 'error');
                        return;
                      }
                      addLlm();
                    }}
                    style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}
                  >
                    {[
                      { key: 'name', label: 'Name', placeholder: 'e.g. Primary Ollama', required: true },
                      { key: 'api_url', label: 'API URL (optional)', placeholder: 'http://ollama-host:11434' },
                      { key: 'api_key', label: 'API Key (optional)', placeholder: 'sk-...' },
                    ].map(({ key, label, placeholder, required }) => (
                      <div key={key}>
                        <label htmlFor={`llm-${key}`} style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                          {label} {required && <span aria-label="required">*</span>}
                        </label>
                        <input
                          id={`llm-${key}`}
                          className="input"
                          required={required}
                          value={(llmForm as any)[key]}
                          onChange={(e) => {
                            const nextValue = e.target.value;
                            setLlmForm((f) => ({ ...f, [key]: nextValue }));
                            if (key === 'api_url' && llmForm.provider === 'ollama_remote') {
                              loadModelsForProvider('ollama_remote', nextValue);
                            }
                            // A changed key/URL invalidates any previously-fetched model list for a non-Ollama
                            // provider — clear it so the admin can't accidentally save a model that doesn't exist
                            // for whatever they just typed, and has to re-fetch (or type a model manually) instead.
                            if ((key === 'api_key' || key === 'api_url') && llmForm.provider !== 'ollama_remote' && apiModels.length > 0) {
                              setApiModels([]);
                              setApiModelsError(null);
                            }
                          }}
                          placeholder={placeholder}
                        />
                      </div>
                    ))}

                    {llmForm.provider !== 'ollama_remote' && (
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                          <label htmlFor="llm-model-name" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            Model Name <span aria-label="required">*</span>
                          </label>
                          <button
                            type="button"
                            onClick={fetchApiModels}
                            disabled={fetchingApiModels || !(llmForm.api_key || '').trim()}
                            className="btn btn-ghost btn-sm"
                            style={{ fontSize: '0.6875rem', padding: '0.2rem 0.6rem' }}
                            title={!(llmForm.api_key || '').trim() ? 'Enter an API key first' : 'Fetch the real model list from this provider'}
                          >
                            {fetchingApiModels ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> : null}
                            Fetch Models
                          </button>
                        </div>
                        {apiModels.length > 0 ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <select
                              id="llm-model-name"
                              className="input"
                              required
                              value={llmForm.model_name}
                              onChange={(e) => setLlmForm((f) => ({ ...f, model_name: e.target.value }))}
                              style={{ background: 'var(--bg-secondary)' }}
                            >
                              <option value="">-- Select a model --</option>
                              {apiModels.map((m) => (
                                <option key={m.id} value={m.id}>{m.label}</option>
                              ))}
                            </select>
                            <p style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                              {apiModels.length} models available from {providerLabel(llmForm.provider)}
                            </p>
                          </div>
                        ) : (
                          <>
                            <input
                              id="llm-model-name"
                              className="input"
                              required
                              value={llmForm.model_name}
                              onChange={(e) => setLlmForm((f) => ({ ...f, model_name: e.target.value }))}
                              placeholder={
                                llmForm.provider === 'openai' ? 'e.g. gpt-4o' :
                                llmForm.provider === 'anthropic' ? 'e.g. claude-sonnet-4-5' :
                                llmForm.provider === 'openrouter' ? 'e.g. openai/gpt-4o' :
                                llmForm.provider === 'grok' ? 'e.g. grok-4' :
                                llmForm.provider === 'mistral' ? 'e.g. mistral-large-latest' :
                                'the exact model name for this provider'
                              }
                            />
                            <p style={{ fontSize: '0.6875rem', color: apiModelsError ? 'var(--amber)' : 'var(--text-muted)', marginTop: 4 }}>
                              {apiModelsError || 'Enter an API key above, then click Fetch Models to pick from a real list — or type the exact model name yourself.'}
                            </p>
                          </>
                        )}
                      </div>
                    )}

                    <div>
                      <label htmlFor="llm-provider" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                        Provider
                      </label>
                      <select
                        id="llm-provider"
                        className="input"
                        value={llmForm.provider}
                        onChange={(e) => {
                          const newProvider = e.target.value;
                          setLlmForm((f) => ({ ...f, provider: newProvider, model_name: '' }));
                          loadModelsForProvider(newProvider, llmForm.api_url || remoteOllamaUrl);
                          // Switching providers invalidates any fetched model list from the previous one.
                          setApiModels([]);
                          setApiModelsError(null);
                        }}
                        style={{ background: 'var(--bg-secondary)' }}
                      >
                        {PROVIDER_OPTIONS.map(({ value, label }) => (
                          <option key={value} value={value}>
                            {label}
                          </option>
                        ))}
                      </select>
                    </div>

                    {llmForm.provider === 'ollama_remote' && (
                      <div>
                        <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                          Model Name *
                        </label>
                        {loadingModels ? (
                          <div style={{ padding: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
                            Fetching available models...
                          </div>
                        ) : availableModels.length > 0 ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <select
                              className="input"
                              value={llmForm.model_name}
                              onChange={(e) => setLlmForm((f) => ({ ...f, model_name: e.target.value }))}
                              style={{ background: 'var(--bg-secondary)' }}
                            >
                              <option value="">-- Select a model --</option>
                              {availableModels.map((m) => (
                                <option key={m} value={m}>
                                  {m}
                                </option>
                              ))}
                            </select>
                            <p style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                              {availableModels.length} models available on remote Ollama
                            </p>
                          </div>
                        ) : (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            <input
                              className="input"
                              required
                              value={llmForm.model_name}
                              onChange={(e) => setLlmForm((f) => ({ ...f, model_name: e.target.value }))}
                              placeholder="e.g. qwen3.5:4b"
                            />
                            <div style={{ background: 'color-mix(in srgb, var(--amber) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--amber) 19%, transparent)', borderRadius: '0.375rem', padding: '0.75rem' }}>
                              <p style={{ fontSize: '0.75rem', color: 'var(--amber)', margin: 0, fontWeight: 500 }}>
                                No models found from remote Ollama
                              </p>
                              <p style={{ fontSize: '0.6875rem', color: 'var(--amber)', margin: '0.25rem 0 0 0', opacity: 0.8 }}>
                                Configure the remote Ollama URL above and test connection, then try again.
                              </p>
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.5rem' }}>
                      <button
                        type="button"
                        onClick={() => {
                          setShowAddLlm(false);
                          setAvailableModels([]);
                          setApiModels([]); setApiModelsError(null);
                          setLlmForm({ name: '', provider: 'ollama_remote', model_name: '', api_url: '', api_key: '', is_default: false });
                        }}
                        className="btn btn-ghost"
                      >
                        Cancel
                      </button>
                      <button type="submit" className="btn btn-primary">
                        Add Provider
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            )}


            <div className="card" style={{ padding: '1.5rem', border: '1px solid var(--border)' }}>
              <div style={{ marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem' }}>Execution Policy</h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                  Set platform-wide execution windows for external scanners.
                </p>
              </div>

              <div style={{ display: 'grid', gap: '0.8rem' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Default Timeout (seconds)</label>
                  <input
                    className="input"
                    type="number"
                    value={toolSettings.tool_timeout_default}
                    onChange={(e) => setToolSettings((t) => ({ ...t, tool_timeout_default: parseInt(e.target.value || '0', 10) || 120 }))}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Nmap Timeout (seconds)</label>
                  <input
                    className="input"
                    type="number"
                    value={toolSettings.tool_timeout_nmap}
                    onChange={(e) => setToolSettings((t) => ({ ...t, tool_timeout_nmap: parseInt(e.target.value || '0', 10) || 300 }))}
                  />
                </div>
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Nuclei Timeout (seconds)</label>
                  <input
                    className="input"
                    type="number"
                    value={toolSettings.tool_timeout_nuclei}
                    onChange={(e) => setToolSettings((t) => ({ ...t, tool_timeout_nuclei: parseInt(e.target.value || '0', 10) || 600 }))}
                  />
                </div>
              </div>
            </div>
              </>
            )}

            {settingsSubtab === 'sso' && (
            <div className="card" style={{ padding: '1.5rem', border: '1px solid var(--border)' }}>
              <div style={{ marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem' }}>SSO Identity Providers</h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                  Configure Google and Microsoft AD SSO in one secured location. Client secrets are encrypted and never returned in plain text.
                </p>
              </div>

              <div style={{ display: 'grid', gap: '1rem' }}>
                <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '0.85rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                    <input
                      type="checkbox"
                      checked={ssoSettings.google_enabled}
                      onChange={(e) => setSsoSettings((s) => ({ ...s, google_enabled: e.target.checked }))}
                    />
                    Enable Google SSO
                  </label>
                  <div style={{ display: 'grid', gap: '0.6rem' }}>
                    <input
                      className="input"
                      placeholder="Google Client ID"
                      value={ssoSettings.google_client_id}
                      onChange={(e) => setSsoSettings((s) => ({ ...s, google_client_id: e.target.value }))}
                    />
                    <input
                      className="input"
                      type="password"
                      placeholder={ssoSettings.google_client_secret_configured ? 'Google Client Secret (leave blank to keep current)' : 'Google Client Secret'}
                      value={ssoSettings.google_client_secret}
                      onChange={(e) => setSsoSettings((s) => ({ ...s, google_client_secret: e.target.value }))}
                    />
                  </div>
                </div>

                <div style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '0.85rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                    <input
                      type="checkbox"
                      checked={ssoSettings.microsoft_enabled}
                      onChange={(e) => setSsoSettings((s) => ({ ...s, microsoft_enabled: e.target.checked }))}
                    />
                    Enable Microsoft AD SSO
                  </label>
                  <div style={{ display: 'grid', gap: '0.6rem' }}>
                    <input
                      className="input"
                      placeholder="Microsoft Client ID"
                      value={ssoSettings.microsoft_client_id}
                      onChange={(e) => setSsoSettings((s) => ({ ...s, microsoft_client_id: e.target.value }))}
                    />
                    <input
                      className="input"
                      type="password"
                      placeholder={ssoSettings.microsoft_client_secret_configured ? 'Microsoft Client Secret (leave blank to keep current)' : 'Microsoft Client Secret'}
                      value={ssoSettings.microsoft_client_secret}
                      onChange={(e) => setSsoSettings((s) => ({ ...s, microsoft_client_secret: e.target.value }))}
                    />
                    <input
                      className="input"
                      placeholder="Tenant ID (or common)"
                      value={ssoSettings.microsoft_tenant_id}
                      onChange={(e) => setSsoSettings((s) => ({ ...s, microsoft_tenant_id: e.target.value }))}
                    />
                  </div>
                </div>

                <div style={{ display: 'grid', gap: '0.5rem' }}>
                  <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Who may sign in</div>
                  <input
                    className="input"
                    placeholder="Allowed e-mail domains, e.g. example.com, corp.example.org"
                    value={ssoSettings.sso_allowed_domains}
                    onChange={(e) => setSsoSettings((s) => ({ ...s, sso_allowed_domains: e.target.value }))}
                  />
                  <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: '0.8125rem' }}>
                    <input
                      type="checkbox"
                      checked={ssoSettings.sso_auto_provision}
                      onChange={(e) => setSsoSettings((s) => ({ ...s, sso_auto_provision: e.target.checked }))}
                    />
                    Create an account (viewer role) on first sign-in
                  </label>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    With this off (the default) only people who already have an SSO-linked account can sign in. Turning it on needs a domain list above;
                    for Microsoft it also needs a single tenant ID (not &quot;common&quot;), because Microsoft does not verify e-mail addresses. An existing
                    account is never taken over by e-mail, except a verified Google address on an allowed domain for a non-administrator.
                  </div>
                </div>

                {ssoMsg && (
                  <div style={{
                    padding: '0.625rem 0.875rem',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '0.8125rem',
                    fontWeight: 600,
                    background: ssoMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 7%, transparent)' : 'color-mix(in srgb, var(--red) 7%, transparent)',
                    border: `1px solid ${ssoMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 24%, transparent)' : 'color-mix(in srgb, var(--red) 24%, transparent)'}`,
                    color: ssoMsg.type === 'success' ? 'var(--green)' : 'var(--red)',
                  }}>
                    {ssoMsg.text}
                  </div>
                )}

                <button onClick={saveSsoSettings} disabled={savingSsoSettings} className="btn btn-primary" style={{ justifyContent: 'center' }}>
                  {savingSsoSettings
                    ? <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Saving SSO...</>
                    : 'Save SSO Configuration'}
                </button>
              </div>
            </div>
            )}

            {settingsSubtab === 'notifications' && (
            <div className="card" style={{ padding: '1.5rem', border: '1px solid var(--border)' }}>
              <div style={{ marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem' }}>Enterprise Notification Delivery</h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                  Configure Microsoft 365 notification channels and parallel webhook delivery for SIEM, Teams, and Slack connectors.
                </p>
              </div>

              <div style={{ display: 'grid', gap: '0.75rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
                  <input
                    type="checkbox"
                    checked={notificationDelivery.enabled}
                    onChange={(e) => setNotificationDelivery((s) => ({ ...s, enabled: e.target.checked }))}
                  />
                  Enable Email Delivery
                </label>

                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>Provider</label>
                  <select
                    className="input"
                    value={notificationDelivery.provider}
                    onChange={(e) => setNotificationDelivery((s) => ({ ...s, provider: e.target.value as 'disabled' | 'microsoft_graph' | 'microsoft_smtp' }))}
                    style={{ background: 'var(--bg-secondary)' }}
                  >
                    <option value="disabled">Disabled</option>
                    <option value="microsoft_graph">Microsoft 365 Graph API</option>
                    <option value="microsoft_smtp">Microsoft / Enterprise SMTP</option>
                  </select>
                </div>

                <input
                  className="input"
                  placeholder="Sender Email (e.g. soc-alerts@company.com)"
                  value={notificationDelivery.sender_email}
                  onChange={(e) => setNotificationDelivery((s) => ({ ...s, sender_email: e.target.value }))}
                />
                <input
                  className="input"
                  placeholder="Reply-To Email (optional)"
                  value={notificationDelivery.reply_to_email}
                  onChange={(e) => setNotificationDelivery((s) => ({ ...s, reply_to_email: e.target.value }))}
                />

                {notificationDelivery.provider === 'microsoft_graph' && (
                  <>
                    <input
                      className="input"
                      placeholder="Microsoft Tenant ID (or common)"
                      value={notificationDelivery.graph_tenant_id}
                      onChange={(e) => setNotificationDelivery((s) => ({ ...s, graph_tenant_id: e.target.value }))}
                    />
                    <input
                      className="input"
                      placeholder="Graph Client ID"
                      value={notificationDelivery.graph_client_id}
                      onChange={(e) => setNotificationDelivery((s) => ({ ...s, graph_client_id: e.target.value }))}
                    />
                    <input
                      className="input"
                      type="password"
                      placeholder={notificationDelivery.graph_client_secret_configured ? 'Graph Client Secret (leave blank to keep current)' : 'Graph Client Secret'}
                      value={notificationDelivery.graph_client_secret}
                      onChange={(e) => setNotificationDelivery((s) => ({ ...s, graph_client_secret: e.target.value }))}
                    />
                  </>
                )}

                {notificationDelivery.provider === 'microsoft_smtp' && (
                  <>
                    <input
                      className="input"
                      placeholder="SMTP Host (e.g. smtp.office365.com)"
                      value={notificationDelivery.smtp_host}
                      onChange={(e) => setNotificationDelivery((s) => ({ ...s, smtp_host: e.target.value }))}
                    />
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.625rem' }}>
                      <input
                        className="input"
                        type="number"
                        placeholder="SMTP Port"
                        value={notificationDelivery.smtp_port}
                        onChange={(e) => setNotificationDelivery((s) => ({ ...s, smtp_port: parseInt(e.target.value || '587', 10) || 587 }))}
                      />
                      <input
                        className="input"
                        placeholder="SMTP Username"
                        value={notificationDelivery.smtp_username}
                        onChange={(e) => setNotificationDelivery((s) => ({ ...s, smtp_username: e.target.value }))}
                      />
                    </div>
                    <input
                      className="input"
                      type="password"
                      placeholder={notificationDelivery.smtp_password_configured ? 'SMTP Password (leave blank to keep current)' : 'SMTP Password'}
                      value={notificationDelivery.smtp_password}
                      onChange={(e) => setNotificationDelivery((s) => ({ ...s, smtp_password: e.target.value }))}
                    />
                    <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                        <input
                          type="checkbox"
                          checked={notificationDelivery.smtp_use_starttls}
                          onChange={(e) => setNotificationDelivery((s) => ({ ...s, smtp_use_starttls: e.target.checked }))}
                        />
                        <span style={{ fontSize: '0.8125rem' }}>Use STARTTLS</span>
                      </label>
                      <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                        <input
                          type="checkbox"
                          checked={notificationDelivery.smtp_use_ssl}
                          onChange={(e) => setNotificationDelivery((s) => ({ ...s, smtp_use_ssl: e.target.checked }))}
                        />
                        <span style={{ fontSize: '0.8125rem' }}>Use SMTPS (SSL)</span>
                      </label>
                    </div>
                  </>
                )}

                <div style={{
                  padding: '0.75rem 1rem',
                  borderRadius: 'var(--radius-md)',
                  fontSize: '0.8125rem',
                  background: 'rgba(6,182,212,0.06)',
                  border: '1px solid rgba(6,182,212,0.22)',
                  color: 'var(--text-secondary)',
                }}>
                  <strong style={{ color: 'var(--cyan)' }}>Slack, Teams &amp; webhook integrations</strong> are managed in the{' '}
                  <button
                    onClick={() => { goSection('plugins'); }}
                    style={{ background: 'none', border: 'none', color: 'var(--cyan)', cursor: 'pointer', padding: 0, font: 'inherit', fontWeight: 700, textDecoration: 'underline' }}
                  >
                    Plugins
                  </button>{' '}
                  tab. Configure them there to receive scan and vulnerability alerts via those channels.
                </div>

                {notificationDeliveryMsg && (
                  <div style={{
                    padding: '0.625rem 0.875rem',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '0.8125rem',
                    fontWeight: 600,
                    background: notificationDeliveryMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 7%, transparent)' : 'color-mix(in srgb, var(--red) 7%, transparent)',
                    border: `1px solid ${notificationDeliveryMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 24%, transparent)' : 'color-mix(in srgb, var(--red) 24%, transparent)'}`,
                    color: notificationDeliveryMsg.type === 'success' ? 'var(--green)' : 'var(--red)',
                  }}>
                    {notificationDeliveryMsg.text}
                  </div>
                )}

                <button onClick={saveNotificationDeliverySettings} disabled={savingNotificationDelivery} className="btn btn-primary" style={{ justifyContent: 'center' }}>
                  {savingNotificationDelivery
                    ? <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Saving Delivery Settings...</>
                    : 'Save Notification Delivery'}
                </button>

                <div style={{ display: 'grid', gap: '0.5rem', marginTop: '0.25rem' }}>
                  <input
                    className="input"
                    placeholder="Test recipient email (optional, defaults to your account)"
                    value={testNotificationEmail}
                    onChange={(e) => setTestNotificationEmail(e.target.value)}
                  />
                  <button
                    onClick={sendTestNotificationDelivery}
                    disabled={testingNotificationDelivery}
                    className="btn btn-ghost"
                    style={{ justifyContent: 'center' }}
                  >
                    {testingNotificationDelivery
                      ? <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Sending Test...</>
                      : 'Send Test Notification'}
                  </button>
                </div>
              </div>
            </div>
            )}
          </div>

          {settingsSubtab === 'tools' && (
          <div className="card" style={{ padding: '1.5rem', border: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '1rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.35rem' }}>Global Tools and MCP Policy</h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                  {enabledToolCount} of {allToolKeys.length} integrations enabled across all users.
                </p>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <button className="btn btn-ghost" onClick={() => setAllToolsEnabled(true)}>Enable All</button>
                <button className="btn btn-ghost" onClick={() => setAllToolsEnabled(false)}>Disable All</button>
              </div>
            </div>

            <div style={{ display: 'grid', gap: '1rem' }}>
              {TOOL_CATEGORIES.map((group) => (
                <div key={group.title} style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '0.9rem' }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 700, marginBottom: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    {group.title}
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.5rem 0.8rem' }}>
                    {group.items.map(({ key, label }) => {
                      const checked = (toolSettings as any)[key] ?? false;
                      return (
                        <label
                          key={key}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.5rem',
                            cursor: 'pointer',
                            borderRadius: 'var(--radius-md)',
                            padding: '0.45rem 0.55rem',
                            border: `1px solid ${checked ? 'color-mix(in srgb, var(--teal) 30%, transparent)' : 'var(--border)'}`,
                            background: checked ? 'color-mix(in srgb, var(--teal) 8%, transparent)' : 'transparent',
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={(e) => setToolSettings((t) => ({ ...t, [key]: e.target.checked }))}
                          />
                          <span style={{ fontSize: '0.8125rem', fontWeight: 500 }}>{label}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
          )}

          {settingsSubtab === 'tools' && (
          <div className="card" style={{ padding: '1.5rem', border: '1px solid var(--border)', marginTop: '1rem' }}>
            <div style={{ marginBottom: '1rem' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.35rem' }}>AI chat: tool-by-tool</h3>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                Fine control on top of the server switches above. A tool with no override here just follows its server&apos;s switch.
                This applies only to what the AI chat may call on its own — it never changes what a real scan can use.
              </p>
            </div>

            {loadingAiTools ? (
              <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Loading tools…</div>
            ) : aiToolCatalog.length === 0 ? (
              <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>No MCP servers discovered yet.</div>
            ) : (
              <div style={{ display: 'grid', gap: '0.9rem' }}>
                {aiToolCatalog.map((srv) => (
                  <div key={srv.server} style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '0.9rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.6rem' }}>
                      <span style={{ fontSize: '0.8125rem', fontWeight: 700 }}>{srv.server}</span>
                      <span style={{
                        fontSize: '0.6875rem', fontWeight: 700, padding: '0.1rem 0.5rem', borderRadius: 999,
                        color: srv.server_enabled ? 'var(--green)' : 'var(--text-muted)',
                        background: srv.server_enabled ? 'color-mix(in srgb, var(--green) 12%, transparent)' : 'color-mix(in srgb, var(--text-muted) 12%, transparent)',
                      }}>
                        server {srv.server_enabled ? 'enabled' : 'disabled'} above
                      </span>
                      {srv.tools.length === 0 && <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>tools discovered on first use</span>}
                    </div>
                    <div style={{ display: 'grid', gap: '0.4rem' }}>
                      {srv.tools.map((tool) => {
                        const key = `${srv.server}.${tool.name}`;
                        const current = toolOverrides[key] ?? null;
                        return (
                          <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', padding: '0.4rem 0.5rem', borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)' }}>
                            <div style={{ minWidth: 0 }}>
                              <div style={{ fontSize: '0.8125rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                {tool.name}
                                {tool.offensive && (
                                  <span title="Exploitation-class: requires SOCIS_AGENT_ALLOW_OFFENSIVE on the server. Cannot be enabled from this page." style={{ fontSize: '0.6875rem', color: 'var(--red)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                                    <Icon name="lock" size={12} /> operator opt-in required
                                  </span>
                                )}
                              </div>
                              {tool.description && <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{tool.description}</div>}
                            </div>
                            {tool.offensive ? (
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', flexShrink: 0 }}>Blocked</span>
                            ) : (
                              <div style={{ display: 'flex', gap: '0.3rem', flexShrink: 0 }}>
                                {([['on', true], ['off', false], ['default', null]] as const).map(([label, value]) => (
                                  <button
                                    key={label}
                                    onClick={() => setToolOverride(srv.server, tool.name, value)}
                                    className="btn btn-ghost"
                                    style={{
                                      padding: '0.25rem 0.6rem', fontSize: '0.75rem',
                                      border: `1px solid ${current === value ? 'var(--cyan)' : 'var(--border)'}`,
                                      background: current === value ? 'var(--cyan-glow)' : 'transparent',
                                    }}
                                  >
                                    {label}
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {toolSettingsMsg && (
              <div style={{
                marginTop: '1rem',
                marginBottom: '0.5rem',
                padding: '0.625rem 0.875rem',
                borderRadius: 'var(--radius-md)',
                background: toolSettingsMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 7%, transparent)' : 'color-mix(in srgb, var(--red) 7%, transparent)',
                border: `1px solid ${toolSettingsMsg.type === 'success' ? 'color-mix(in srgb, var(--green) 24%, transparent)' : 'color-mix(in srgb, var(--red) 24%, transparent)'}`,
                color: toolSettingsMsg.type === 'success' ? 'var(--green)' : 'var(--red)',
                fontSize: '0.8125rem',
                fontWeight: 600,
              }}>
                {toolSettingsMsg.text}
              </div>
            )}

            <div style={{ marginTop: '0.75rem' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                One Save covers the server switches above and the tool-by-tool choices together.
              </div>
              <button onClick={saveToolPolicy} disabled={savingToolSettings} className="btn btn-primary">
                {savingToolSettings
                  ? <><Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> Saving Policy...</>
                  : 'Save Global Policy'}
              </button>
            </div>
          </div>
          )}
        </div>
      )}
    </SettingsShell>
  );
}

export default function AdminPage() {
  return <Suspense fallback={null}><AdminPageInner /></Suspense>;
}
