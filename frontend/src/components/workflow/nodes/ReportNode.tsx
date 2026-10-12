'use client';
// @ts-ignore
import { Handle, Position, useReactFlow } from '@xyflow/react';
import { FileText } from 'lucide-react';
import { NodeHeader, NodeBody, NodeField, statusRingStyle } from './shared';
import type { WFNodeData } from '@/lib/types';

export function ReportNode({ id, data }: { id: string; data: WFNodeData }) {
  const { deleteElements } = useReactFlow();
  return (
    <div style={{ ...statusRingStyle(data), minWidth: 160 }}>
      <Handle type="target" position={Position.Top} style={{ background: 'var(--chart-orange)' }} />
      <Handle type="target" id="t-left"  position={Position.Left}  style={{ background: 'var(--chart-orange)', width: 8, height: 8 }} />
      <Handle type="target" id="t-right" position={Position.Right} style={{ background: 'var(--chart-orange)', width: 8, height: 8 }} />
      <NodeHeader icon={<FileText size={13} />} label={data.label || 'Generate Report'} accent="var(--orange)" execStatus={data.execStatus}
        onDelete={() => deleteElements({ nodes: [{ id }] })} />
      <NodeBody>
        <NodeField label="template" value={data.template ?? 'standard'} />
      </NodeBody>
    </div>
  );
}
