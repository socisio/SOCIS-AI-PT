'use client';
import { useState, useEffect, useRef, useCallback } from 'react';
import { Send, Bot, User, Loader2, RefreshCw, Plus, Trash2, MessageSquare, Shield, Zap, Search, FileText, Globe, ChevronRight, Terminal, HelpCircle, Square, Clock3, Database, Pin, Flag, ListChecks, CheckCircle2 } from 'lucide-react';
import MarkdownRenderer from '@/components/MarkdownRenderer';
import UiIcon from '@/components/ui/Icon';
import type { IconName } from '@/components/ui/Icon';
import { notify } from '@/lib/dialogs';
import ChatModelPicker from '@/components/ChatModelPicker';
import MCPHelpModal from '@/components/MCPHelpModal';
import { chatSessionsApi, settingsApi } from '@/lib/api';
import { LLMProviderOption, fetchLlmOptions } from '@/components/LLMProviderSelector';
import { normalizeProvider } from '@/lib/providers';
import type { ChatMessage } from '@/lib/types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? '';

const WELCOME_CONTENT = '__socis_welcome_v2__';
const LEGACY_WELCOME_PREFIX = '👋 **SOCIS-AI-PT**';
const isWelcomeMsg = (content: string) =>
  content === WELCOME_CONTENT || content.startsWith(LEGACY_WELCOME_PREFIX);

let msgCounter = 0;
const mkId = () => `msg-${Date.now()}-${++msgCounter}`;

function welcomeMsg(): ChatMessage {
  return { id: mkId(), role: 'assistant', content: WELCOME_CONTENT, timestamp: new Date().toISOString() };
}

interface SessionSummary {
  id: string;
  title: string;
  updated_at: string;
  provider: string;
  model_name?: string | null;
}

interface ActivityEvent {
  id: string;
  category: 'session' | 'model' | 'chat' | 'system';
  text: string;
  at: string;
}

interface ActionTask {
  id: string;
  messageId: string;
  title: string;
  status: 'open' | 'done';
}

interface ChatSessionArtifacts {
  pinned_message_ids: string[];
  report_message_ids: string[];
  action_tasks: ActionTask[];
  activity_events: ActivityEvent[];
}



const QUICK_PROMPTS = [
  { title: 'Vulnerability Prioritization', prompt: 'What are the critical findings I should prioritize first?', tag: 'Risk' },
  { title: 'CVE Threat Intel', prompt: 'Search for CVE-2021-44228 (Log4Shell) exploitation details', tag: 'Intel' },
  { title: 'Scan Interpretation', prompt: 'Analyze the nmap output above and list all vulnerabilities found', tag: 'Analysis' },
  { title: 'Remediation Plan', prompt: 'Generate a remediation plan for the high severity vulnerabilities', tag: 'Response' },
];

const initialArtifacts = (): ChatSessionArtifacts => ({
  pinned_message_ids: [],
  report_message_ids: [],
  action_tasks: [],
  activity_events: [
    { id: mkId(), category: 'system', text: 'Workspace initialized', at: new Date().toISOString() },
  ],
});

export default function AIChatPage() {
  // ── Session list (sidebar) ─────────────────────────────────
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [loadingSessions, setLoadingSessions] = useState(true);

  // ── Active chat ────────────────────────────────────────────
  const [messages, setMessages] = useState<ChatMessage[]>(() => [welcomeMsg()]);
  const [input, setInput] = useState('');
  const [streamingBySessionId, setStreamingBySessionId] = useState<Record<string, boolean>>({});
  const [provider, setProvider] = useState<string>('ollama_remote');
  const [llmProviders, setLlmProviders] = useState<LLMProviderOption[]>([]);
  const [loadingProviders, setLoadingProviders] = useState(false);
  const [selectedModel, setSelectedModel] = useState<string>('');
  const [savingSession, setSavingSession] = useState(false);
  const [savingArtifacts, setSavingArtifacts] = useState(false);
  const [hydratingArtifacts, setHydratingArtifacts] = useState(false);
  const [modelSaveMsg, setModelSaveMsg] = useState('');
  const [showHelp, setShowHelp] = useState(false);
  const [wsOpen, setWsOpen] = useState(false);
  // The conversation list can be hidden (like the platform sidebar); the choice is remembered on this device.
  const [histOpen, setHistOpen] = useState(true);
  const searchRef = useRef<HTMLInputElement>(null);
  const setHist = (open: boolean) => {
    setHistOpen(open);
    try { localStorage.setItem('socis.chat.history', open ? 'open' : 'closed'); } catch { /* private mode */ }
  };
  useEffect(() => {
    try { if (localStorage.getItem('socis.chat.history') === 'closed') setHistOpen(false); } catch { /* private mode */ }
  }, []);
  // The provider + model the user last saved (every change in the picker saves it), used for the star in the model chip.
  const [savedDefault, setSavedDefault] = useState<{ provider: string; model: string } | null>(null);
  const [wsTab, setWsTab] = useState<'pinned' | 'report' | 'tasks' | 'activity'>('pinned');
  const [sessionQ, setSessionQ] = useState('');
  const [activityEvents, setActivityEvents] = useState<ActivityEvent[]>(initialArtifacts().activity_events);
  const [pinnedMessageIds, setPinnedMessageIds] = useState<string[]>(initialArtifacts().pinned_message_ids);
  const [reportMessageIds, setReportMessageIds] = useState<string[]>(initialArtifacts().report_message_ids);
  const [actionTasks, setActionTasks] = useState<ActionTask[]>(initialArtifacts().action_tasks);

  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const saveArtifactsTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const abortControllersRef = useRef<Record<string, AbortController>>({});
  const activeSessionIdRef = useRef<string | null>(null);
  // Caches in-progress messages per session so switching back during streaming
  // shows live tokens instead of the stale DB snapshot.
  const liveMessagesRef = useRef<Record<string, ChatMessage[]>>({});
  // Prevents concurrent openSession calls from racing each other.
  const openSessionLockRef = useRef<string | null>(null);

  const activeStreamKey = activeSessionId ?? 'draft';
  const activeSessionStreaming = !!streamingBySessionId[activeStreamKey];

  // ── Fetch session list ─────────────────────────────────────
  const fetchSessions = useCallback(async () => {
    setLoadingSessions(true);
    try {
      const res = await chatSessionsApi.list();
      setSessions(res.data.sessions || []);
    } catch {
      setSessions([]);
    } finally {
      setLoadingSessions(false);
    }
  }, []);

  const pushActivity = useCallback((category: ActivityEvent['category'], text: string) => {
    setActivityEvents(prev => [
      { id: mkId(), category, text, at: new Date().toISOString() },
      ...prev,
    ].slice(0, 80));
  }, []);

  // Per-session draft persistence helpers
  const sessionDraftKey = (id: string | null) => id ? `socis_chat_draft_${id}` : 'socis_chat_input';

  // Load global draft on mount (before any session is active)
  useEffect(() => {
    const saved = localStorage.getItem('socis_chat_input');
    if (saved) setInput(saved);
  }, []);

  // Save draft under the active session key (or global key when no session)
  useEffect(() => {
    localStorage.setItem(sessionDraftKey(activeSessionId), input);
  }, [input, activeSessionId]);

  useEffect(() => {
    fetchSessions();
    // Load provider + model from DB (server-side user settings)
    settingsApi.getLlmSettings().then(res => {
      const s = res.data || {};
      if (s.chat_provider) setProvider(normalizeProvider(s.chat_provider));
      if (s.chat_model) setSelectedModel(s.chat_model);
      if (s.chat_provider && s.chat_model) setSavedDefault({ provider: normalizeProvider(s.chat_provider), model: s.chat_model });
    }).catch(() => {});
    // Load admin-configured LLM providers
    setLoadingProviders(true);
    fetchLlmOptions().then(opts => {
      setLlmProviders(opts);
    }).finally(() => setLoadingProviders(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    activeSessionIdRef.current = activeSessionId;
  }, [activeSessionId]);

  useEffect(() => {
    return () => {
      Object.values(abortControllersRef.current).forEach(controller => controller.abort());
      abortControllersRef.current = {};
    };
  }, []);

  // ── Open an existing session ───────────────────────────────
  const openSession = useCallback(async (id: string) => {
    // Prevent a second concurrent open from racing the first
    if (openSessionLockRef.current === id) return;
    openSessionLockRef.current = id;

    try {
      const res = await chatSessionsApi.get(id);
      const s = res.data;
      // If a different session was clicked while this request was in-flight, bail out
      if (openSessionLockRef.current !== id) return;
      setActiveSessionId(s.id);
      // If a live stream is running for this session, show in-memory tokens
      // rather than the stale DB snapshot.
      const liveMessages = liveMessagesRef.current[id];
      const isStreaming = !!streamingBySessionId[id];
      setMessages(liveMessages && isStreaming ? liveMessages : (s.messages.length > 0 ? s.messages : [welcomeMsg()]));
      setProvider(normalizeProvider(s.provider));
      setSelectedModel(s.model_name || '');
      // Restore per-session draft
      const draft = localStorage.getItem(sessionDraftKey(s.id)) || '';
      setInput(draft);

      setHydratingArtifacts(true);
      try {
        const artifactsRes = await chatSessionsApi.getArtifacts(s.id);
        const art = artifactsRes.data;
        setPinnedMessageIds(Array.isArray(art.pinned_message_ids) ? art.pinned_message_ids : []);
        setReportMessageIds(Array.isArray(art.report_message_ids) ? art.report_message_ids : []);
        setActionTasks(Array.isArray(art.action_tasks) ? art.action_tasks : []);
        setActivityEvents(Array.isArray(art.activity_events) ? art.activity_events : []);
      } catch {
        const defaults = initialArtifacts();
        setPinnedMessageIds(defaults.pinned_message_ids);
        setReportMessageIds(defaults.report_message_ids);
        setActionTasks(defaults.action_tasks);
        setActivityEvents(defaults.activity_events);
      } finally {
        setHydratingArtifacts(false);
      }

      pushActivity('session', `Opened session: ${s.title || s.id.slice(0, 8)}`);
    } catch {
      fetchSessions();
    } finally {
      // Release lock only if it still belongs to this call
      if (openSessionLockRef.current === id) openSessionLockRef.current = null;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetchSessions, pushActivity]);

  // ── Create new session ─────────────────────────────────────
  const newChat = useCallback(async () => {
    const welcome = welcomeMsg();
    try {
      const res = await chatSessionsApi.create({
        title: 'New Chat',
        provider,
        model_name: selectedModel || undefined,
        messages: [welcome],
      });
      const s = res.data;
      setActiveSessionId(s.id);
      setMessages([welcome]);
      setInput('');
      localStorage.removeItem('socis_chat_input');
      setSessions(prev => [s, ...prev]);

      const defaults = initialArtifacts();
      setPinnedMessageIds(defaults.pinned_message_ids);
      setReportMessageIds(defaults.report_message_ids);
      setActionTasks(defaults.action_tasks);
      setActivityEvents(defaults.activity_events);

      pushActivity('session', 'Started a new chat session');
    } catch {
      setActiveSessionId(null);
      setMessages([welcome]);
      setInput('');
    }
  }, [provider, selectedModel, pushActivity]);

  // ── Delete session ─────────────────────────────────────────
  const deleteSession = useCallback(async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try { await chatSessionsApi.delete(id); } catch {}
    setSessions(prev => prev.filter(s => s.id !== id));
    if (activeSessionId === id) {
      setActiveSessionId(null);
      setMessages([welcomeMsg()]);
      const defaults = initialArtifacts();
      setPinnedMessageIds(defaults.pinned_message_ids);
      setReportMessageIds(defaults.report_message_ids);
      setActionTasks(defaults.action_tasks);
      setActivityEvents(defaults.activity_events);
    }
  }, [activeSessionId]);

  // ── Debounced persist ──────────────────────────────────────
  const persistSession = useCallback((
    msgs: ChatMessage[], prov: string, model: string, sessionId: string
  ) => {
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(async () => {
      try {
        setSavingSession(true);
        await chatSessionsApi.update(sessionId, {
          provider: prov,
          model_name: model || undefined,
          messages: msgs,
        });
        setSessions(prev =>
          prev.map(s => s.id === sessionId ? { ...s, updated_at: new Date().toISOString() } : s)
        );
      } catch {}
      finally { setSavingSession(false); }
    }, 1500);
  }, []);

  const persistArtifacts = useCallback((sessionId: string, payload: ChatSessionArtifacts) => {
    if (saveArtifactsTimerRef.current) clearTimeout(saveArtifactsTimerRef.current);
    saveArtifactsTimerRef.current = setTimeout(async () => {
      try {
        setSavingArtifacts(true);
        await chatSessionsApi.updateArtifacts(sessionId, payload);
      } catch {
        // no-op: artifacts persistence failures should not block chat UX
      } finally {
        setSavingArtifacts(false);
      }
    }, 1000);
  }, []);

  const handleProviderChange = (id: string, defaultModel: string) => {
    setProvider(id);
    setSelectedModel(defaultModel);
    settingsApi.saveLlmSettings({ chat_provider: id, chat_model: defaultModel }).then(() => setSavedDefault({ provider: normalizeProvider(id), model: defaultModel })).catch(() => {});
    pushActivity('model', `Provider switched to ${id}`);
  };

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (!activeSessionId || hydratingArtifacts) return;
    persistArtifacts(activeSessionId, {
      pinned_message_ids: pinnedMessageIds,
      report_message_ids: reportMessageIds,
      action_tasks: actionTasks,
      activity_events: activityEvents,
    });
  }, [
    activeSessionId,
    hydratingArtifacts,
    pinnedMessageIds,
    reportMessageIds,
    actionTasks,
    activityEvents,
    persistArtifacts,
  ]);

  // ── Send message ───────────────────────────────────────────
  const sendMessage = useCallback(async () => {
    if (!input.trim() || activeSessionStreaming) return;

    const requestProvider = provider;
    const requestModel = selectedModel;

    // Create session on first message if none active
    let sessionId = activeSessionId;
    if (!sessionId) {
      try {
        const res = await chatSessionsApi.create({
          title: 'New Chat',
          provider: requestProvider,
          model_name: requestModel || undefined,
          messages: messages,
        });
        sessionId = res.data.id;
        setActiveSessionId(sessionId);
        setSessions(prev => [res.data, ...prev]);
      } catch {}
    }

    const streamKey = sessionId ?? 'draft';

    const userMsg: ChatMessage = {
      id: mkId(), role: 'user', content: input.trim(), timestamp: new Date().toISOString(),
    };
    const assistantId = mkId();
    const assistantPlaceholder: ChatMessage = {
      id: assistantId, role: 'assistant', content: '', timestamp: new Date().toISOString(),
    };

    let persistedMessages = [...messages, userMsg, assistantPlaceholder];
    liveMessagesRef.current[streamKey] = persistedMessages;
    setMessages(persistedMessages);
    setInput('');
    setStreamingBySessionId(prev => ({ ...prev, [streamKey]: true }));
    pushActivity('chat', `Prompt submitted (${userMsg.content.length} chars)`);
    const startedAt = Date.now();

    const abort = new AbortController();
    abortControllersRef.current[streamKey] = abort;

    try {
      // Build conversation history: exclude welcome messages, empty placeholders,
      // and cap at last 20 turns to stay within backend's 100-message / 100KB limits.
      const history = messages
        .filter(m => !isWelcomeMsg(m.content) && m.content.trim() !== '')
        .slice(-20)
        .map(m => ({ role: m.role, content: m.content }));
      // Append the new user message (messages state hasn't updated yet)
      const chatPayload = [...history, { role: 'user', content: userMsg.content }];

      const res = await fetch(`${API_BASE}/api/v1/llm/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        signal: abort.signal,
        body: JSON.stringify({
          messages: chatPayload,
          provider: requestProvider,
          model_name: requestModel || undefined,
          stream: true,
        }),
      });

      if (!res.ok) {
        let detail = `HTTP ${res.status}`;
        try {
          const errBody = await res.json();
          detail = errBody?.detail || detail;
        } catch {}
        throw new Error(detail);
      }
      if (!res.body) throw new Error('No streaming response');
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const data = JSON.parse(line.slice(6));
            if (data.type === 'token' && data.content) {
              persistedMessages = persistedMessages.map(m =>
                m.id === assistantId ? { ...m, content: m.content + data.content } : m
              );
              liveMessagesRef.current[streamKey] = persistedMessages;
              if (activeSessionIdRef.current === sessionId) {
                setMessages(persistedMessages);
              }
            } else if (data.type === 'error') {
              const errorText = `[LLM Error: ${data.message || 'Unknown error'}]`;
              persistedMessages = persistedMessages.map(m =>
                m.id === assistantId ? { ...m, content: errorText } : m
              );
              liveMessagesRef.current[streamKey] = persistedMessages;
              if (activeSessionIdRef.current === sessionId) {
                setMessages(persistedMessages);
              }
            }
          } catch {}
        }
      }
    } catch (e: any) {
      if (e.name !== 'AbortError') {
        persistedMessages = persistedMessages.map(m =>
          m.id === assistantId ? { ...m, content: `[Error: ${e.message || 'Failed to reach LLM'}]` } : m
        );
        if (activeSessionIdRef.current === sessionId) {
          setMessages(persistedMessages);
        }
      }
    } finally {
      delete abortControllersRef.current[streamKey];
      delete liveMessagesRef.current[streamKey];
      setStreamingBySessionId(prev => ({ ...prev, [streamKey]: false }));
      const durationMs = Date.now() - startedAt;
      if (abort.signal.aborted) {
        pushActivity('chat', `Generation stopped at ${(durationMs / 1000).toFixed(1)}s`);
      } else {
        pushActivity('chat', `Response completed in ${(durationMs / 1000).toFixed(1)}s`);
      }
      // Clear the draft for the session that just completed
      if (sessionId) localStorage.removeItem(sessionDraftKey(sessionId));
      inputRef.current?.focus();
      if (sessionId) {
        persistSession(persistedMessages, requestProvider, requestModel, sessionId);
      }
    }
  }, [input, activeSessionStreaming, provider, selectedModel, activeSessionId, messages, persistSession, pushActivity]);

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  };

  const stopStreaming = () => {
    const key = activeSessionId ?? 'draft';
    abortControllersRef.current[key]?.abort();
    pushActivity('chat', 'Stop requested by operator');
  };

  const saveDefaultModel = async () => {
    if (!selectedModel) return;
    try {
      await settingsApi.saveLlmSettings({ chat_provider: provider, chat_model: selectedModel });
      setSavedDefault({ provider: normalizeProvider(provider), model: selectedModel });
      setModelSaveMsg(`Default model saved: ${selectedModel}`);
      pushActivity('model', `Default model set to ${selectedModel}`);
      setTimeout(() => setModelSaveMsg(''), 2600);
    } catch {
      setModelSaveMsg('Failed to save default model');
      pushActivity('system', 'Failed to persist default model');
      setTimeout(() => setModelSaveMsg(''), 2600);
    }
  };

  const cleanSnippet = (content: string) => content.replace(/\s+/g, ' ').trim().slice(0, 120);

  const togglePinned = (messageId: string) => {
    const wasPinned = pinnedMessageIds.includes(messageId);
    setPinnedMessageIds(prev => prev.includes(messageId) ? prev.filter(id => id !== messageId) : [...prev, messageId]);
    pushActivity('chat', `Pin ${wasPinned ? 'removed' : 'added'}`);
  };

  const toggleReportQueue = (messageId: string) => {
    const wasQueued = reportMessageIds.includes(messageId);
    setReportMessageIds(prev => prev.includes(messageId) ? prev.filter(id => id !== messageId) : [...prev, messageId]);
    pushActivity('chat', `Report queue ${wasQueued ? 'removed' : 'updated'}`);
  };

  const createTaskFromMessage = (message: ChatMessage) => {
    if (actionTasks.some(t => t.messageId === message.id)) return;
    setActionTasks(prev => ([
      ...prev,
      { id: mkId(), messageId: message.id, title: cleanSnippet(message.content) || 'Follow-up action', status: 'open' },
    ]));
    pushActivity('chat', 'Created follow-up task from response');
  };

  const toggleTaskStatus = (taskId: string) => {
    setActionTasks(prev => prev.map(t => t.id === taskId ? { ...t, status: t.status === 'open' ? 'done' : 'open' } : t));
    pushActivity('chat', 'Task status changed');
  };

  const getMessageById = (id: string) => messages.find(m => m.id === id);

  const activityColor: Record<ActivityEvent['category'], string> = {
    system: 'var(--text-secondary)',
    session: 'var(--green)',
    model: 'var(--cyan)',
    chat: 'var(--amber)',
  };

  const fmtDate = (iso: string) => {
    const d = new Date(iso);
    const now = new Date();
    const diff = (now.getTime() - d.getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return d.toLocaleDateString();
  };

  // ── presentation helpers (no behaviour lives here) ──
  const visible = messages.filter((m) => !isWelcomeMsg(m.content));
  const isEmpty = visible.length === 0;
  const lastAssistantId = [...visible].reverse().find((m) => m.role === 'assistant')?.id;
  const connectedCount = llmProviders.filter((p) => p.connected).length;
  const openTasks = actionTasks.filter((t) => t.status !== 'done').length;
  const wsCount = pinnedMessageIds.length + reportMessageIds.length + openTasks;

  const groupOf = (iso: string): string => {
    const startToday = new Date(new Date().getFullYear(), new Date().getMonth(), new Date().getDate()).getTime();
    const t = new Date(iso).getTime();
    if (t >= startToday) return 'Today';
    if (t >= startToday - 86400000) return 'Yesterday';
    if (t >= startToday - 7 * 86400000) return 'Previous 7 days';
    return 'Older';
  };
  const q = sessionQ.trim().toLowerCase();
  const filteredSessions = sessions.filter((x) => !q || x.title.toLowerCase().includes(q));
  const sessionGroups = ['Today', 'Yesterday', 'Previous 7 days', 'Older']
    .map((g) => ({ g, items: filteredSessions.filter((x) => groupOf(x.updated_at) === g) }))
    .filter((x) => x.items.length > 0);

  const CAPS: { icon: IconName; title: string; text: string; prompt: string }[] = [
    { icon: 'shield', title: 'CVE & Threat Intelligence', text: 'Look up a CVE with its EPSS score and KEV status.', prompt: 'Look up CVE-2024-3094 and tell me its EPSS score, KEV status and exploit availability.' },
    { icon: 'bug', title: 'Exploit Analysis', text: 'Assess whether a finding is actually exploitable here.', prompt: 'Assess whether this finding is actually exploitable in my environment: ' },
    { icon: 'file', title: 'Scan Result Interpretation', text: 'Paste Nmap or Nuclei output and get what matters.', prompt: 'Interpret this scan output and tell me what matters most:\n\n' },
    { icon: 'tasks', title: 'Remediation Guidance', text: 'Turn critical findings into an ordered fix plan.', prompt: 'Turn the critical findings into an ordered remediation plan.' },
    { icon: 'globe', title: 'OSINT & Recon Assistance', text: 'Summarise what is exposed about a target domain.', prompt: 'Summarise what is publicly exposed about this domain: ' },
    { icon: 'terminal', title: 'MCP Tool Integration', text: 'Run connected scanning tools from the conversation.', prompt: 'Which MCP tools are connected, and how do I run a port scan with them?' },
  ];
  const TAG_ICON: Record<string, IconName> = { Risk: 'target', Intel: 'shield', Analysis: 'file', Response: 'tasks' };

  const copyMessage = (text: string) => {
    navigator.clipboard?.writeText(text).then(() => notify('Copied', 'success')).catch(() => notify('Could not copy', 'error'));
  };

  const saveStatus = savingSession ? 'Saving…' : savingArtifacts ? 'Syncing…' : activeSessionId ? 'Saved' : '';
  const isDefaultModel = !!savedDefault && savedDefault.provider === normalizeProvider(provider) && savedDefault.model === selectedModel;

  return (
    <div className={`chat${histOpen ? '' : ' hist-collapsed'}`}>
      {showHelp && <MCPHelpModal onClose={() => setShowHelp(false)} />}

      {/* ── Conversations ─────────────────────────────────── */}
      <div className={`chat-side${histOpen ? '' : ' collapsed'}`}>
        {!histOpen ? (
          <div className="rail">
            <button className="icon-btn" onClick={() => setHist(true)} title="Show conversations" aria-label="Show conversations"><UiIcon name="chevr" size={16} /></button>
            <button className="icon-btn" onClick={newChat} title="New chat" aria-label="New chat"><UiIcon name="plus" size={17} /></button>
            <button className="icon-btn" onClick={() => { setHist(true); setTimeout(() => searchRef.current?.focus(), 60); }} title="Search conversations" aria-label="Search conversations"><UiIcon name="search" size={16} /></button>
            <div style={{ flex: 1 }} />
            <i title={`${connectedCount} ${connectedCount === 1 ? 'provider' : 'providers'} connected`} style={{ width: 8, height: 8, borderRadius: '50%', background: connectedCount > 0 ? 'var(--green)' : 'var(--text-muted)', display: 'inline-block', marginBottom: 6 }} />
          </div>
        ) : (<>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <button onClick={newChat} className="btn btn-primary" style={{ flex: 1, justifyContent: 'center', minHeight: 36 }}>
            <UiIcon name="plus" size={16} /> New chat
          </button>
          <button className="icon-btn" onClick={() => setHist(false)} title="Hide conversations" aria-label="Hide conversations"><UiIcon name="chevl" size={16} /></button>
        </div>
        <div className="sel" style={{ width: '100%' }}>
          <UiIcon name="search" size={14} />
          <input
            ref={searchRef} value={sessionQ} onChange={(e) => setSessionQ(e.target.value)} placeholder="Search conversations" aria-label="Search conversations"
            style={{ flex: 1, minWidth: 0, background: 'none', border: 'none', outline: 'none', color: 'var(--text-primary)', fontSize: '0.78rem', fontFamily: 'inherit' }}
          />
        </div>
        <div style={{ overflowY: 'auto', flex: 1, minHeight: 0 }}>
          {loadingSessions ? (
            <div className="muted" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem', padding: '0.75rem 0.5rem' }}>
              <Loader2 size={13} className="animate-spin" /> Loading…
            </div>
          ) : sessions.length === 0 ? (
            <div className="muted" style={{ textAlign: 'center', fontSize: '0.78rem', padding: '2.2rem 1rem', lineHeight: 1.55 }}>
              <div style={{ display: 'inline-flex', width: 38, height: 38, borderRadius: 10, alignItems: 'center', justifyContent: 'center', background: 'var(--bg-hover)', color: 'var(--text-muted)', marginBottom: '0.6rem' }}>
                <UiIcon name="chat" size={18} />
              </div>
              <br /><strong style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>No conversations yet</strong><br />
              Your chats are saved here so you can pick them up later.
            </div>
          ) : sessionGroups.length === 0 ? (
            <div className="muted" style={{ textAlign: 'center', fontSize: '0.78rem', padding: '1.5rem 0.5rem' }}>No conversations match your search.</div>
          ) : sessionGroups.map(({ g, items }) => (
            <div key={g}>
              <div className="grp">{g}</div>
              {items.map((x) => (
                <div
                  key={x.id} role="button" tabIndex={0} className={`sess${activeSessionId === x.id ? ' on' : ''}`}
                  onClick={() => openSession(x.id)} onKeyDown={(e) => { if (e.key === 'Enter') openSession(x.id); }}
                  style={{ cursor: 'pointer' }}
                >
                  <span className="t" style={{ paddingRight: 22 }}>{x.title}</span>
                  <small>{fmtDate(x.updated_at)}</small>
                  <button
                    onClick={(e) => deleteSession(x.id, e)} title="Delete session" aria-label={`Delete ${x.title}`}
                    style={{ position: 'absolute', right: 6, top: 8, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2, display: 'flex' }}
                  ><UiIcon name="trash" size={13} /></button>
                </div>
              ))}
            </div>
          ))}
        </div>
        <div className="side-foot">
          <i style={{ width: 8, height: 8, borderRadius: '50%', background: connectedCount > 0 ? 'var(--green)' : 'var(--text-muted)', display: 'inline-block' }} />
          {connectedCount} {connectedCount === 1 ? 'provider' : 'providers'} connected
        </div>
        </>)}
      </div>

      {/* ── Conversation ──────────────────────────────────── */}
      <div className="chat-main">
        <div className="chat-head">
          <div className="ttl">
            <span className="tile"><UiIcon name="shield" size={17} /></span>
            <h2 style={{ whiteSpace: 'nowrap' }}>AI Security Assistant</h2>
            <span className="pill green"><i className="d" />Online</span>
            {saveStatus && <span className="muted" style={{ fontSize: '0.72rem' }}>{saveStatus}</span>}
          </div>
          <div className="end">
            <ChatModelPicker
              providers={llmProviders} loading={loadingProviders} provider={provider} model={selectedModel} isDefault={isDefaultModel}
              onProviderChange={(id, defaultModel) => handleProviderChange(id, defaultModel)}
              onModelChange={(m) => {
                setSelectedModel(m);
                settingsApi.saveLlmSettings({ chat_provider: provider, chat_model: m }).then(() => setSavedDefault({ provider: normalizeProvider(provider), model: m })).catch(() => {});
              }}
            />
            <button
              className="icon-btn" title="Refresh provider list" aria-label="Refresh provider list"
              onClick={() => { setLoadingProviders(true); fetchLlmOptions().then((opts) => setLlmProviders(opts)).finally(() => setLoadingProviders(false)); }}
            ><UiIcon name="refresh" size={16} /></button>
            <button className="icon-btn" onClick={() => setShowHelp(true)} title="How to use MCP tools" aria-label="How to use MCP tools"><UiIcon name="help" size={17} /></button>
            <button className="wsbtn" onClick={() => setWsOpen((o) => !o)} aria-pressed={wsOpen} title="Session workspace: pinned insights, report queue and tasks"
              style={wsOpen ? { borderColor: 'var(--cyan)', color: 'var(--cyan)' } : undefined}>
              <UiIcon name="panel" size={14} />{wsCount > 0 && <em>{wsCount}</em>}
            </button>
          </div>
        </div>

        <div className="stream">
          {isEmpty ? (
            <>
              <div className="hero">
                <span className="tile big"><UiIcon name="spark" size={24} /></span>
                <h1>How can I help with your assessment?</h1>
                <p>{provider ? `Connected to ${llmProviders.find((p) => normalizeProvider(p.id) === normalizeProvider(provider))?.label ?? provider}` : 'Pick a provider to begin'}{selectedModel ? ` · ${selectedModel}` : ''}</p>
              </div>
              <div className="caps">
                {CAPS.map((c) => (
                  <button key={c.title} className="cap" onClick={() => { setInput(c.prompt); inputRef.current?.focus(); }}>
                    <span className="h"><span><UiIcon name={c.icon} size={16} /></span>{c.title}</span>
                    <p>{c.text}</p>
                  </button>
                ))}
              </div>
            </>
          ) : (
            <div className="col">
              {visible.map((msg) => msg.role === 'user' ? (
                <div key={msg.id} className="msg me"><div className="bubble" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{msg.content}</div></div>
              ) : (
                <div key={msg.id} className="msg">
                  <span className="ai-av"><UiIcon name="shield" size={15} /></span>
                  <div className="ai-body">
                    <div className="who"><b>SOCIS AI</b><span>{activeSessionStreaming && msg.id === lastAssistantId ? 'generating…' : selectedModel}</span></div>
                    {msg.content
                      ? <div style={{ wordBreak: 'break-word' }}><MarkdownRenderer content={msg.content} /></div>
                      : (activeSessionStreaming ? <Loader2 size={14} className="animate-spin" color="var(--cyan)" /> : null)}
                    {msg.content && (
                      <div className="acts">
                        <button onClick={() => copyMessage(msg.content)} title="Copy"><UiIcon name="copy" size={13} /> Copy</button>
                        <button onClick={() => togglePinned(msg.id)} className={pinnedMessageIds.includes(msg.id) ? 'on' : ''} title="Pin insight">
                          <UiIcon name="pin" size={13} /> {pinnedMessageIds.includes(msg.id) ? 'Pinned' : 'Pin'}
                        </button>
                        <button onClick={() => toggleReportQueue(msg.id)} className={reportMessageIds.includes(msg.id) ? 'on' : ''} title="Add to report queue">
                          <UiIcon name="file" size={13} /> {reportMessageIds.includes(msg.id) ? 'In report' : 'Add to report'}
                        </button>
                        <button onClick={() => createTaskFromMessage(msg)} title="Create follow-up task"><UiIcon name="tasks" size={13} /> Create task</button>
                      </div>
                    )}
                  </div>
                </div>
              ))}
              <div ref={bottomRef} />
            </div>
          )}
        </div>

        <div className="composer-wrap">
          <div className="col">
            {!isEmpty && (
              <div className="chips">
                {QUICK_PROMPTS.map((p) => (
                  <button key={p.title} className="chip2" onClick={() => setInput(p.prompt)}><UiIcon name={TAG_ICON[p.tag] ?? 'spark'} size={13} />{p.title}</button>
                ))}
              </div>
            )}
            <div className="composer">
              <textarea
                ref={inputRef} value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={handleKey}
                placeholder="Ask about vulnerabilities, paste scan output, or request a CVE lookup…" aria-label="Message" disabled={activeSessionStreaming} rows={1}
                style={{ flex: 1, background: 'none', border: 'none', outline: 'none', color: 'var(--text-primary)', fontSize: '0.875rem', lineHeight: 1.6, resize: 'none', fontFamily: 'var(--font-sans)', maxHeight: 160, overflowY: 'auto', padding: '0.35rem 0' }}
              />
              {activeSessionStreaming ? (
                <button className="send stop" onClick={stopStreaming} title="Stop generating" aria-label="Stop generating" style={{ border: '1px solid var(--border-strong)', cursor: 'pointer' }}><UiIcon name="x" size={16} /></button>
              ) : (
                <button className="send" onClick={sendMessage} disabled={!input.trim()} title="Send" aria-label="Send" style={{ border: 'none', cursor: 'pointer', opacity: input.trim() ? 1 : 0.5 }}><UiIcon name="send" size={16} /></button>
              )}
            </div>
            <div className="chat-hint">Enter to send · Shift+Enter for a new line · AI answers can be wrong: verify findings before you act.</div>
          </div>
        </div>
      </div>

      {/* ── Session workspace (collapsible) ───────────────── */}
      {wsOpen && (
        <aside className="ws" aria-label="Session workspace">
          <div className="ws-head">Session workspace
            <button className="icon-btn" style={{ marginLeft: 'auto', width: 26, height: 26 }} onClick={() => setWsOpen(false)} aria-label="Close workspace"><UiIcon name="x" size={14} /></button>
          </div>
          <div className="tabs2" role="tablist">
            {([['pinned', 'Pinned', pinnedMessageIds.length], ['report', 'Report', reportMessageIds.length], ['tasks', 'Tasks', openTasks], ['activity', 'Activity', 0]] as const).map(([k, label, n]) => (
              <span key={k} role="tab" aria-selected={wsTab === k} tabIndex={0} className={wsTab === k ? 'on' : ''} onClick={() => setWsTab(k)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setWsTab(k); } }} style={{ cursor: 'pointer' }}>
                {label}{n > 0 && <em>{n}</em>}
              </span>
            ))}
          </div>
          <div className="ws-body" style={{ overflowY: 'auto' }}>
            {wsTab === 'pinned' && (pinnedMessageIds.length === 0
              ? <div className="muted" style={{ fontSize: '0.78rem' }}>Pin any answer to keep it here. Items stay with this conversation.</div>
              : pinnedMessageIds.map((id) => { const m = getMessageById(id); return m ? (
                <div key={id} className="pin">{cleanSnippet(m.content)}
                  <small><UiIcon name="pin" size={11} /> Pinned<button onClick={() => togglePinned(id)} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.6875rem' }}>Unpin</button></small>
                </div>) : null; }))}
            {wsTab === 'report' && (reportMessageIds.length === 0
              ? <div className="muted" style={{ fontSize: '0.78rem' }}>Add answers to the report queue to collect them for a report.</div>
              : reportMessageIds.map((id) => { const m = getMessageById(id); return m ? (
                <div key={id} className="pin">{cleanSnippet(m.content)}
                  <small><UiIcon name="file" size={11} /> In report queue<button onClick={() => toggleReportQueue(id)} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.6875rem' }}>Remove</button></small>
                </div>) : null; }))}
            {wsTab === 'tasks' && (actionTasks.length === 0
              ? <div className="muted" style={{ fontSize: '0.78rem' }}>Create a follow-up task from any answer.</div>
              : actionTasks.map((t) => (
                <button key={t.id} onClick={() => toggleTaskStatus(t.id)} className="pin" style={{ textAlign: 'left', cursor: 'pointer', display: 'flex', gap: '0.5rem', alignItems: 'flex-start', width: '100%' }}>
                  <span style={{ color: t.status === 'done' ? 'var(--green)' : 'var(--text-muted)', marginTop: 1 }}><UiIcon name={t.status === 'done' ? 'check' : 'tasks'} size={14} /></span>
                  <span style={{ textDecoration: t.status === 'done' ? 'line-through' : 'none' }}>{t.title}</span>
                </button>
              )))}
            {wsTab === 'activity' && (activityEvents.length === 0
              ? <div className="muted" style={{ fontSize: '0.78rem' }}>Nothing yet.</div>
              : activityEvents.slice(0, 30).map((ev) => (
                <div key={ev.id} className="pin">
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: 2 }}>
                    <i style={{ width: 7, height: 7, borderRadius: '50%', background: activityColor[ev.category], display: 'inline-block' }} />
                    <span style={{ fontSize: '0.6875rem', color: activityColor[ev.category] }}>{ev.category}</span>
                    <span style={{ marginLeft: 'auto', fontSize: '0.6875rem', color: 'var(--text-muted)' }}>{fmtDate(ev.at)}</span>
                  </span>
                  {ev.text}
                </div>
              )))}
          </div>
        </aside>
      )}
    </div>
  );
}
