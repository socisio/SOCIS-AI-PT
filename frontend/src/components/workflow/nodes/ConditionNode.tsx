'use client';
// @ts-ignore
import { Handle, Position, useReactFlow } from '@xyflow/react';
import { GitBranch } from 'lucide-react';
import { NodeHeader, NodeBody, NodeField, statusRingStyle } from './shared';
import type { WFNodeData } from '@/lib/types';

function formatCondExpr(expr: string | undefined): string {
  if (!expr) return '—';
  if (expr === 'true')  return '✓ Always YES';
  if (expr === 'false') return '✗ Always NO';
  const parts = expr.split(':');
  if (parts.length < 2) return expr; // legacy flat keyword
  const [tool, check, param] = parts;
  const checkLabel = check.replace(/_/g, ' ');
  const toolLabel  = tool.toUpperCase();
  return param
    ? `${toolLabel} › ${checkLabel} : ${param}`
    : `${toolLabel} › ${checkLabel}`;
}

export function ConditionNode({ id, data }: { id: string; data: WFNodeData }) {
  const { deleteElements } = useReactFlow();
  return (
    <div style={{ ...statusRingStyle(data), minWidth: 170 }}>
      <Handle type="target" position={Position.Top} style={{ background: 'var(--chart-amber)' }} />
      <Handle type="target" id="t-left"  position={Position.Left}  style={{ background: 'var(--chart-amber)', width: 8, height: 8 }} />
      <Handle type="target" id="t-right" position={Position.Right} style={{ background: 'var(--chart-amber)', width: 8, height: 8 }} />
      <NodeHeader icon={<GitBranch size={13} />} label={data.label || 'Condition'} accent="var(--amber)" execStatus={data.execStatus}
        onDelete={() => deleteElements({ nodes: [{ id }] })} />
      <NodeBody>
        <NodeField label="if" value={formatCondExpr(data.expression)} />
        <div style={{ display: 'flex', gap: 8, marginTop: 8, fontSize: '0.6875rem' }}>
          <span style={{ color: 'var(--green)' }}>✓ yes</span>
          <span style={{ color: 'var(--red)' }}>✗ no</span>
        </div>
        {data.execOutput && (
          <div style={{ marginTop: 4, fontSize: '0.6875rem', color: 'var(--text-secondary)' }}>
            → {data.execOutput}
          </div>
        )}
      </NodeBody>
      {/* Two source handles: yes (left) and no (right) */}
      <Handle
        type="source"
        position={Position.Bottom}
        id="yes"
        style={{ left: '30%', background: 'var(--chart-green)' }}
      />
      <Handle
        type="source"
        position={Position.Bottom}
        id="no"
        style={{ left: '70%', background: 'var(--chart-red)' }}
      />
    </div>
  );
}
