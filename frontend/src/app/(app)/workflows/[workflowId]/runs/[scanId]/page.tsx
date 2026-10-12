'use client';

/**
 * SOCIS-AI-PT — Visual Workflow Run Results Page
 * Shows the execution canvas in read-only mode, with results per node.
 * Route: /workflows/[workflowId]/runs/[scanId]
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  type NodeTypes,
  BackgroundVariant,
// @ts-ignore
} from '@xyflow/react';
// @ts-ignore
import '@xyflow/react/dist/style.css';

import {
  ShieldAlert, Clock, CheckCircle, AlertCircle, XCircle,
  RefreshCw, ChevronDown, ChevronRight, Brain,
} from 'lucide-react';

import { workflowsApi, scansApi } from '@/lib/api';
import type {
  WFNode, WFEdge, WFNodeEvent, Vulnerability, Scan,
  WorkflowDefinition,
} from '@/lib/types';

import { StartNode }     from '@/components/workflow/nodes/StartNode';
import { ToolNode }      from '@/components/workflow/nodes/ToolNode';
import { LlmNode }       from '@/components/workflow/nodes/LlmNode';
import { ConditionNode } from '@/components/workflow/nodes/ConditionNode';
import { ReportNode }    from '@/components/workflow/nodes/ReportNode';
import MetasploitTerminal from '@/components/MetasploitTerminal';

const NODE_TYPES: NodeTypes = {
  start:     StartNode     as any,
  tool:      ToolNode      as any,
  llm:       LlmNode       as any,
  condition: ConditionNode as any,
  report:    ReportNode    as any,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--amber)',
  low: 'var(--green)', info: 'var(--blue)',
};

function extractMetasploitSessionId(output?: string): number | null {
  if (!output || typeof output !== 'string') return null;
  // 1. Try JSON (interactive_handoff result or similar)
  try {
    const parsed = JSON.parse(output);
    if (typeof parsed?.session_id === 'number') return parsed.session_id;
    if (parsed?.interactive_handoff && parsed?.session_id) {
      const sid = parseInt(String(parsed.session_id), 10);
      return Number.isFinite(sid) ? sid : null;
    }
    // msf_session_ids array (run_exploit result stored as JSON)
    if (Array.isArray(parsed?.msf_session_ids) && parsed.msf_session_ids.length > 0) {
      const sid = parseInt(String(parsed.msf_session_ids[0]), 10);
      if (Number.isFinite(sid)) return sid;
    }
  } catch { /* not JSON – fall through to text regex */ }
  // 2. MSF console text: "[+] Meterpreter session 2 opened ..."
  const m = output.match(/(?:meterpreter|shell|command)\s+session\s+(\d+)\s+opened/i)
         ?? output.match(/session\s+(\d+)\s+opened/i);
  if (m) return parseInt(m[1], 10);
  return null;
}

// ── Vuln card ─────────────────────────────────────────────────────────────────

function VulnCard({ v }: { v: Vulnerability }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{
      border: `1px solid color-mix(in srgb, ${SEVERITY_COLORS[v.severity] ?? 'var(--border)'} 20%, transparent)`,
      borderLeft: `3px solid ${SEVERITY_COLORS[v.severity] ?? 'var(--text-muted)'}`,
      borderRadius: 'var(--radius-md)', background: 'var(--bg-card)', marginBottom: 8, overflow: 'hidden',
    }}>
      <div onClick={() => setOpen(!open)} style={{ padding: '0.625rem 1rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 10 }}>
        <ShieldAlert size={14} color={SEVERITY_COLORS[v.severity]} />
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--text-primary)' }}>{v.vuln_name}</div>
          <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
            {v.port && `Port ${v.port}`}{v.service && ` · ${v.service}`}{v.cve_id && ` · ${v.cve_id}`}
          </div>
        </div>
        <span style={{ fontSize: '0.6875rem', fontWeight: 700, padding: '2px 7px', borderRadius: 'var(--radius-sm)', background: `color-mix(in srgb, ${SEVERITY_COLORS[v.severity] ?? 'var(--border)'} 13%, transparent)`, color: SEVERITY_COLORS[v.severity] ?? 'var(--text-secondary)' }}>
          {v.severity}
        </span>
      </div>
      {open && v.description && (
        <div style={{ padding: '0 1rem 0.75rem', fontSize: '0.75rem', color: 'var(--text-secondary)', borderTop: '1px solid var(--border)', paddingTop: 8 }}>
          {v.description}
        </div>
      )}
    </div>
  );
}

// ── Node output drawer ────────────────────────────────────────────────────────

function NodeOutput({ nodeId, outputs }: { nodeId: string | null; outputs: Record<string, WFNodeEvent> }) {
  if (!nodeId) return (
    <div style={{ padding: '2rem 1.25rem', color: 'var(--text-muted)', fontSize: '0.75rem', textAlign: 'center' }}>
      Click a node to see its output
    </div>
  );
  const ev = outputs[nodeId];
  if (!ev) return (
    <div style={{ padding: '1rem 1.25rem', color: 'var(--text-muted)', fontSize: '0.75rem' }}>No output recorded for this node.</div>
  );
  return (
    <div style={{ padding: '1rem 1.25rem' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
        <span style={{ fontWeight: 700, fontSize: '0.8125rem', color: 'var(--text-primary)' }}>{nodeId}</span>
        {ev.type === 'node_complete' && !ev.skipped && <CheckCircle size={13} color="var(--green)" />}
        {ev.type === 'node_failed' && <AlertCircle size={13} color="var(--red)" />}
        {ev.skipped && <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>skipped</span>}
        {ev.duration_ms && <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>{ev.duration_ms}ms</span>}
      </div>
      {ev.error && <div style={{ color: 'var(--red)', fontSize: '0.75rem', marginBottom: 8 }}>⚠ {ev.error}</div>}
      {ev.output && (
        <pre style={{
          background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)',
          padding: '0.75rem', fontSize: '0.6875rem', color: 'var(--text-secondary)', overflowX: 'auto',
          whiteSpace: 'pre-wrap', maxHeight: 'calc(100vh - 300px)', overflowY: 'auto',
        }}>
          {ev.output}
        </pre>
      )}
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

function ResultsInner() {
  const params = useParams<{ workflowId: string; scanId: string }>();
  const searchParams = useSearchParams();
  const router = useRouter();
  const { workflowId, scanId } = params;

  const [scan, setScan] = useState<Scan | null>(null);
  const [nodes, setNodes] = useState<WFNode[]>([]);
  const [edges, setEdges] = useState<WFEdge[]>([]);
  const [nodeOutputs, setNodeOutputs] = useState<Record<string, WFNodeEvent>>({});
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'canvas' | 'vulns' | 'ai' | 'log' | 'terminal'>('canvas');
  const [wsLog, setWsLog] = useState<WFNodeEvent[]>([]);
  const [handoffSessions, setHandoffSessions] = useState<number[]>([]);
  const [terminalSessionId, setTerminalSessionId] = useState<number | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const tab = searchParams.get('tab');
    if (tab === 'terminal') setActiveTab('terminal');
  }, [searchParams]);

  const loadScan = useCallback(async () => {
    const r = await scansApi.get(scanId);
    const scanData: Scan = r.data;
    setScan(scanData);

    const fromResults = (scanData?.tool_results ?? [])
      .map((tr: any) => {
        // 1. Try raw_output (console text or JSON string)
        const fromRaw = extractMetasploitSessionId(tr?.raw_output);
        if (fromRaw !== null) return fromRaw;
        // 2. Fallback: check parsed_output.msf_session_ids (run_exploit result object)
        const po = tr?.parsed_output;
        if (po && Array.isArray(po.msf_session_ids) && po.msf_session_ids.length > 0) {
          const sid = parseInt(String(po.msf_session_ids[0]), 10);
          if (Number.isFinite(sid)) return sid;
        }
        // 3. Fallback: check parsed_output.session_id when it's a real MSF ID (number)
        if (po && typeof po.session_id === 'number') return po.session_id;
        return null;
      })
      .filter((v: number | null): v is number => v !== null);
    if (fromResults.length > 0) {
      setHandoffSessions(prev => Array.from(new Set([...prev, ...fromResults])));
      setTerminalSessionId(prev => prev ?? fromResults[0]);
    }

    // When scan is already finished, reconstruct the event log from tool_results
    // so the Event Log tab isn't empty (WS is skipped for completed scans).
    if (['completed', 'failed', 'cancelled'].includes(scanData.status)) {
      const toolResults = scanData.tool_results ?? [];
      if (toolResults.length > 0) {
        const now = scanData.completed_at ?? new Date().toISOString();
        const reconstructed: WFNodeEvent[] = toolResults.map((tr: any) => ({
          type: (tr.exit_code === 0 || tr.exit_code == null) ? 'node_complete' : 'node_failed',
          scan_id: scanId,
          node_id: tr.id ?? tr.tool_name,
          node_type: 'tool',
          tool: tr.tool_name,
          output: tr.raw_output?.slice(0, 3000),
          duration_ms: tr.duration_ms,
          success: tr.exit_code === 0 || tr.exit_code == null,
          timestamp: now,
        }));
        setWsLog(prev => prev.length === 0 ? reconstructed : prev);
        // Also populate nodeOutputs keyed by tool_name for the node drawer
        const outputMap: Record<string, WFNodeEvent> = {};
        reconstructed.forEach(ev => { outputMap[ev.node_id] = ev; });
        setNodeOutputs(prev => Object.keys(prev).length === 0 ? outputMap : prev);
      }
    }
  }, [scanId]);

  useEffect(() => {
    loadScan();
    // Load workflow definition for canvas
    workflowsApi.get(workflowId).then(r => {
      const wf: WorkflowDefinition = r.data;
      setNodes(wf.nodes as WFNode[] ?? []);
      setEdges(wf.edges as WFEdge[] ?? []);
    }).catch(() => {});
  }, [workflowId, loadScan]);

  // Live WS while scan is still running
  useEffect(() => {
    if (!scan) return;
    if (['completed', 'failed', 'cancelled'].includes(scan.status)) return;

    const apiBase = process.env.NEXT_PUBLIC_API_URL ||
      (typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8000');
    const token = document.cookie.split('; ').find(c => c.startsWith('access_token='))?.split('=')[1] ?? '';
    const wsUrl = apiBase.replace(/^http/, 'ws') + `/ws/scan/${scanId}?token=${token}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (ev) => {
      try {
        const msg: WFNodeEvent = JSON.parse(ev.data);
        if (['node_start', 'node_complete', 'node_failed'].includes(msg.type)) {
          setWsLog(prev => [...prev.slice(-200), msg]);
          if (msg.type !== 'node_start') {
            setNodeOutputs(prev => ({ ...prev, [msg.node_id]: msg }));
            // Try text/JSON output first, then msf_session_ids from WS event
            let sid = extractMetasploitSessionId(msg.output);
            if (sid === null && Array.isArray((msg as any).msf_session_ids) && (msg as any).msf_session_ids.length > 0) {
              sid = parseInt(String((msg as any).msf_session_ids[0]), 10);
              if (!Number.isFinite(sid)) sid = null;
            }
            if (sid !== null) {
              setHandoffSessions(prev => Array.from(new Set([...prev, sid!])));
              setTerminalSessionId(prev => prev ?? sid!);
            }
          }
          const execStatus =
            msg.type === 'node_start'    ? 'running'   :
            msg.type === 'node_complete' ? (msg.skipped ? 'skipped' : 'completed') :
            'failed';
          setNodes(prev => prev.map(n =>
            n.id === msg.node_id
              ? { ...n, data: { ...n.data, execStatus, execOutput: msg.output?.slice(0, 300), execDuration: msg.duration_ms } }
              : n
          ));
        }
        if ((msg as any).type === 'status' && ((msg as any).status === 'completed' || (msg as any).status === 'failed')) {
          loadScan();
        }
      } catch {}
    };
    ws.onclose = () => loadScan();

    return () => ws.close();
  }, [scan?.status, scanId, loadScan]);

  const statusColor = {
    pending:   'var(--text-secondary)', running: 'var(--cyan)', analyzing: 'var(--purple)',
    completed: 'var(--green)', failed:  'var(--red)',  cancelled: 'var(--text-muted)',
  }[scan?.status ?? 'pending'] ?? 'var(--text-secondary)';

  const duration = scan?.started_at && scan?.completed_at
    ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
    : null;

  const S: Record<string, React.CSSProperties> = {
    root:   { display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg-primary)' },
    topBar: { display: 'flex', alignItems: 'center', gap: 16, padding: '0 1.5rem', height: 56, borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0 },
    stat:   { display: 'flex', flexDirection: 'column', gap: 1 },
    statV:  { fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' },
    statL:  { fontSize: 10, color: 'var(--text-muted)' },
    body:   { display: 'flex', flex: 1, overflow: 'hidden' },
    canvas: { flex: 1, position: 'relative' },
    right:  { width: 340, borderLeft: '1px solid var(--border)', background: 'var(--bg-secondary)', overflowY: 'auto', flexShrink: 0 },
  };

  const tabStyle = (active: boolean): React.CSSProperties => ({
    padding: '6px 14px', fontSize: 12, fontWeight: 600, cursor: 'pointer', border: 'none',
    background: 'none', borderBottom: active ? '2px solid var(--cyan)' : '2px solid transparent',
    color: active ? 'var(--cyan)' : 'var(--text-muted)', whiteSpace: 'nowrap',
  });

  return (
    <div style={S.root}>
      {/* Top stats bar */}
      <div style={S.topBar}>
        <button onClick={() => router.push(`/workflows/builder?id=${workflowId}`)}
          style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.75rem' }}>
          ← Builder
        </button>
        <div style={{ width: 1, height: 28, background: 'var(--border)' }} />

        <div style={S.stat}>
          <span style={{ ...S.statV, color: statusColor }}>{scan?.status ?? '—'}</span>
          <span style={S.statL}>Status</span>
        </div>
        <div style={S.stat}>
          <span style={S.statV}>{scan?.target ?? '—'}</span>
          <span style={S.statL}>Target</span>
        </div>
        <div style={S.stat}>
          <span style={S.statV}>{duration != null ? `${duration}s` : '—'}</span>
          <span style={S.statL}>Duration</span>
        </div>
        <div style={S.stat}>
          <span style={S.statV}>{scan?.vulnerabilities?.length ?? 0}</span>
          <span style={S.statL}>Vulns</span>
        </div>
        <div style={S.stat}>
          <span style={{ ...S.statV, color: SEVERITY_COLORS[scan?.risk_level ?? ''] ?? 'var(--text-secondary)' }}>
            {scan?.risk_level ?? 'Unknown'}
          </span>
          <span style={S.statL}>Risk</span>
        </div>
        <div style={{ flex: 1 }} />
        {['running', 'analyzing', 'pending'].includes(scan?.status ?? '') && (
          <button onClick={loadScan} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <RefreshCw size={14} />
          </button>
        )}
      </div>

      <div style={S.body}>
        {/* Canvas or alternate tabs */}
        <div style={S.canvas}>
          {/* Tab bar */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', paddingLeft: 8 }}>
            {(['canvas', 'vulns', 'ai', 'terminal', 'log'] as const).map(t => (
              <button key={t} style={tabStyle(activeTab === t)} onClick={() => setActiveTab(t)}>
                {t === 'canvas' ? 'Canvas' : t === 'vulns' ? `Vulnerabilities (${scan?.vulnerabilities?.length ?? 0})` : t === 'ai' ? 'AI Analysis' : t === 'terminal' ? 'Terminal' : 'Event Log'}
              </button>
            ))}
          </div>

          {activeTab === 'canvas' && (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={NODE_TYPES}
              onNodeClick={(_: unknown, n: WFNode) => setSelectedNodeId(n.id)}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable={true}
              colorMode="dark"
              fitView
              style={{ background: 'var(--bg-primary)', height: 'calc(100% - 37px)' }}
              defaultEdgeOptions={{ style: { stroke: 'var(--border)', strokeWidth: 2 } }}
            >
              <Background variant={BackgroundVariant.Dots} color="var(--border)" gap={20} />
              <Controls />
              <MiniMap style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }} nodeColor={() => 'var(--text-muted)'} maskColor="color-mix(in srgb, var(--border) 53%, transparent)" />
            </ReactFlow>
          )}

          {activeTab === 'vulns' && (
            <div style={{ padding: '1rem 1.5rem', overflowY: 'auto', height: 'calc(100% - 37px)' }}>
              {!scan?.vulnerabilities?.length
                ? <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', textAlign: 'center', marginTop: '3rem' }}>No vulnerabilities recorded.</div>
                : scan.vulnerabilities.map(v => <VulnCard key={v.id} v={v} />)
              }
            </div>
          )}

          {activeTab === 'ai' && (
            <div style={{ padding: '1rem 1.5rem', overflowY: 'auto', height: 'calc(100% - 37px)' }}>
              {!scan?.ai_analyses?.length
                ? <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', textAlign: 'center', marginTop: '3rem' }}>No AI analysis yet.</div>
                : scan.ai_analyses.map((a, i) => (
                  <div key={i} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '1rem', marginBottom: 12 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <Brain size={14} color="var(--purple)" />
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.8125rem' }}>AI Analysis</span>
                      {a.risk_level && (
                        <span style={{ fontSize: '0.6875rem', color: SEVERITY_COLORS[a.risk_level] ?? 'var(--text-secondary)', marginLeft: 'auto' }}>
                          Risk: {a.risk_level}
                        </span>
                      )}
                    </div>
                    <pre style={{ whiteSpace: 'pre-wrap', fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                      {a.response}
                    </pre>
                  </div>
                ))
              }
            </div>
          )}

          {activeTab === 'terminal' && (
            <div style={{ padding: '1rem 1.25rem', overflowY: 'auto', height: 'calc(100% - 37px)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Session:</label>
                <select
                  value={terminalSessionId ?? ''}
                  onChange={(e) => setTerminalSessionId(e.target.value ? parseInt(e.target.value, 10) : null)}
                  style={{
                    background: 'var(--bg-card)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.75rem',
                    padding: '0.35rem 0.45rem',
                    minWidth: 160,
                  }}
                >
                  {handoffSessions.length === 0 && <option value="">No handoff session detected</option>}
                  {handoffSessions.map((sid) => (
                    <option key={sid} value={sid}>Session {sid}</option>
                  ))}
                </select>
              </div>
              <MetasploitTerminal
                scanId={scanId}
                sessionId={terminalSessionId}
                height={390}
              />
            </div>
          )}

          {activeTab === 'log' && (
            <div style={{ padding: '0.75rem 1rem', overflowY: 'auto', height: 'calc(100% - 37px)', fontFamily: 'monospace', fontSize: '0.6875rem' }}>
              {wsLog.length === 0
                ? <div style={{ color: 'var(--text-muted)', marginTop: '2rem', textAlign: 'center' }}>No events recorded.</div>
                : wsLog.map((ev, i) => {
                    // Resolve human-readable label from nodes list
                    const nodeData = nodes.find(n => n.id === ev.node_id)?.data;
                    const label = nodeData?.label || ev.tool || ev.node_id;

                    // Parse output for a one-line summary
                    let summary = '';
                    if (ev.output) {
                      try {
                        const p = JSON.parse(ev.output);
                        const tool = ev.tool ?? '';
                        if (tool === 'nmap') {
                          const open = (p.open_ports ?? []).length;
                          summary = `${open} open port${open !== 1 ? 's' : ''}`;
                        } else if (tool === 'nuclei') {
                          const f = (p.findings ?? p.results ?? []).length;
                          summary = `${f} finding${f !== 1 ? 's' : ''}`;
                        } else if (tool === 'sqlmap' || tool === 'sqlmap_full') {
                          summary = p.vulnerable ? `⚠ VULNERABLE — ${p.phase === 'complete' ? `${(p.databases ?? []).length} DB(s) dumped` : 'detected only'}` : '✓ not injectable';
                        } else if (tool === 'metasploit') {
                          const sessions = (p.sessions_opened ?? []).length;
                          summary = sessions > 0 ? `🔴 ${sessions} session${sessions !== 1 ? 's' : ''} opened` : p.attempted_modules ? `${p.attempted_modules} modules tried — no session` : 'no session';
                        } else if (tool === 'cve') {
                          summary = `${p.total ?? (p.results ?? []).length} CVE(s)`;
                        } else if (tool === 'cisa_kev') {
                          summary = p.in_kev ? '🚨 IN KEV' : 'not in KEV';
                        } else if (tool === 'epss') {
                          summary = p.epss_score_pct ?? (p.epss_score != null ? `${(p.epss_score * 100).toFixed(2)}%` : '');
                        } else if (tool === 'masscan') {
                          summary = `${(p.open_ports ?? []).length} open port(s)`;
                        } else if (typeof p === 'object') {
                          // Generic fallback: pick first meaningful string field
                          const msg = p.message ?? p.status ?? p.summary ?? '';
                          if (msg) summary = String(msg).slice(0, 80);
                        }
                      } catch {
                        // Not JSON — show trimmed plain text
                        const plain = ev.output.replace(/\s+/g, ' ').trim();
                        summary = plain.slice(0, 100) + (plain.length > 100 ? '…' : '');
                      }
                    }

                    const statusColor =
                      ev.type === 'node_start'    ? 'var(--cyan)' :
                      ev.type === 'node_complete' ? (ev.skipped ? 'var(--text-muted)' : 'var(--green)') : 'var(--red)';
                    const statusLabel =
                      ev.type === 'node_start'    ? 'START' :
                      ev.skipped                  ? 'SKIP'  :
                      ev.type === 'node_complete' ? 'DONE'  : 'FAIL';

                    return (
                      <div key={i} style={{
                        marginBottom: 6, padding: '6px 8px',
                        borderLeft: `3px solid color-mix(in srgb, ${statusColor} 27%, transparent)`,
                        background: i % 2 === 0 ? 'color-mix(in srgb, var(--text-primary) 2%, transparent)' : 'transparent',
                        borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
                      }}>
                        {/* Row 1: time · badge · label · duration */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                          <span style={{ color: 'var(--blue)', flexShrink: 0, fontSize: '0.6875rem' }}>
                            {new Date(ev.timestamp).toLocaleTimeString()}
                          </span>
                          <span style={{
                            flexShrink: 0, fontSize: '0.6875rem', fontWeight: 700,
                            padding: '1px 5px', borderRadius: 'var(--radius-sm)',
                            background: `color-mix(in srgb, ${statusColor} 13%, transparent)`, color: statusColor,
                            border: `1px solid color-mix(in srgb, ${statusColor} 33%, transparent)`,
                          }}>
                            {statusLabel}
                          </span>
                          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{label}</span>
                          {ev.tool && ev.tool !== label && (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.6875rem' }}>({ev.tool})</span>
                          )}
                          {ev.duration_ms != null && (
                            <span style={{ color: 'var(--blue)', marginLeft: 'auto', flexShrink: 0, fontSize: '0.6875rem' }}>
                              {ev.duration_ms >= 1000 ? `${(ev.duration_ms / 1000).toFixed(1)}s` : `${ev.duration_ms}ms`}
                            </span>
                          )}
                        </div>
                        {/* Row 2: summary or error */}
                        {summary && ev.type !== 'node_start' && (
                          <div style={{ color: ev.type === 'node_failed' ? 'var(--red)' : 'var(--text-muted)', fontSize: '0.6875rem', marginTop: 2, paddingLeft: 2 }}>
                            {summary}
                          </div>
                        )}
                        {ev.skipped && (
                          <div style={{ color: 'var(--text-muted)', fontSize: '0.6875rem', marginTop: 2, paddingLeft: 2 }}>skipped — condition not met</div>
                        )}
                        {ev.error && (
                          <div style={{ color: 'var(--red)', fontSize: '0.6875rem', marginTop: 2, paddingLeft: 2 }}>⚠ {ev.error}</div>
                        )}
                      </div>
                    );
                  })
              }
            </div>
          )}
        </div>

        {/* Right: node output drawer */}
        <div style={S.right}>
          <div style={{ padding: '10px 14px 6px', borderBottom: '1px solid var(--border)', fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em' }}>
            Node Output
          </div>
          <NodeOutput nodeId={selectedNodeId} outputs={nodeOutputs} />
        </div>
      </div>
    </div>
  );
}

export default function WorkflowRunResultsPage() {
  return (
    <ReactFlowProvider>
      <ResultsInner />
    </ReactFlowProvider>
  );
}
