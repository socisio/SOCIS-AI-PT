'use client';
// @ts-ignore
import { Handle, Position, useReactFlow } from '@xyflow/react';
import { Play } from 'lucide-react';
import { NodeHeader, NodeBody, NodeField, statusRingStyle } from './shared';
import type { WFNodeData } from '@/lib/types';

const WF_TYPE_LABELS: Record<string, string> = {
  network: 'target',
  cve:     'cve id',
  keyword: 'keyword',
  url:     'url',
  webapp:  'url',
  osint:   'target',
  exploit: 'cve id',
  pentest: 'target',
  code:    'project',
  ssl:     'target',
};

export function StartNode({ id, data }: { id: string; data: WFNodeData }) {
  const { deleteElements } = useReactFlow();
  const typeLabel = WF_TYPE_LABELS[data.workflow_type ?? 'network'] ?? 'target';
  const valueDisplay = data.target || '(set at run time)';
  return (
    <div style={{ ...statusRingStyle(data), borderColor: 'var(--green)', minWidth: 160 }}>
      <NodeHeader icon={<Play size={13} />} label="Start" accent="var(--green)" execStatus={data.execStatus}
        onDelete={() => deleteElements({ nodes: [{ id }] })} />
      <NodeBody>
        <NodeField label={typeLabel} value={valueDisplay} />
      </NodeBody>
      <Handle type="source" position={Position.Bottom} style={{ background: 'var(--chart-green)' }} />
      <Handle type="source" id="s-left"  position={Position.Left}  style={{ background: 'var(--chart-green)', width: 8, height: 8 }} />
      <Handle type="source" id="s-right" position={Position.Right} style={{ background: 'var(--chart-green)', width: 8, height: 8 }} />
    </div>
  );
}
