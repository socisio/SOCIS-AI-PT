'use client';
// @ts-ignore
import { Handle, Position, useReactFlow } from '@xyflow/react';
import { Brain } from 'lucide-react';
import { NodeHeader, NodeBody, NodeField, statusRingStyle } from './shared';
import type { WFNodeData } from '@/lib/types';
import { providerLabel } from '@/lib/providers';

export function LlmNode({ id, data }: { id: string; data: WFNodeData }) {
  const { deleteElements } = useReactFlow();
  return (
    <div style={{ ...statusRingStyle(data), minWidth: 190 }}>
      <Handle type="target" position={Position.Top} style={{ background: 'var(--chart-purple)' }} />
      <Handle type="target" id="t-left"  position={Position.Left}  style={{ background: 'var(--chart-purple)', top: '38%', width: 8, height: 8 }} />
      <Handle type="target" id="t-right" position={Position.Right} style={{ background: 'var(--chart-purple)', top: '38%', width: 8, height: 8 }} />
      <NodeHeader icon={<Brain size={13} />} label={data.label || 'LLM Analysis'} accent="var(--purple)" execStatus={data.execStatus}
        onDelete={() => deleteElements({ nodes: [{ id }] })} />
      <NodeBody>
        <NodeField label="provider" value={providerLabel(data.provider)} />
        <NodeField label="model" value={data.model} />
        {data.prompt && (
          <div
            style={{
              marginTop: 5, fontSize: '0.6875rem', color: 'var(--text-muted)',
              borderTop: '1px solid var(--border)', paddingTop: 4,
              overflow: 'hidden', maxHeight: 44,
            }}
          >
            {data.prompt.slice(0, 120)}{data.prompt.length > 120 ? '…' : ''}
          </div>
        )}
        {data.execStatus === 'running' && (
          <div style={{ marginTop: 6, fontSize: '0.6875rem', color: 'var(--purple)' }}>Generating…</div>
        )}
      </NodeBody>
      <Handle type="source" position={Position.Bottom} style={{ background: 'var(--chart-purple)' }} />
      <Handle type="source" id="s-left"  position={Position.Left}  style={{ background: 'var(--chart-purple)', top: '62%', width: 8, height: 8 }} />
      <Handle type="source" id="s-right" position={Position.Right} style={{ background: 'var(--chart-purple)', top: '62%', width: 8, height: 8 }} />
    </div>
  );
}
