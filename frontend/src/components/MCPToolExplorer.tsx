'use client';

import { useState, useMemo } from 'react';
import { Search, X, ChevronRight, Filter } from 'lucide-react';
import { MCPServer, ToolSchema } from '@/lib/types';

interface MCPToolExplorerProps {
  servers: MCPServer[];
  onToolSelect?: (tool: ToolSchema, server: MCPServer) => void;
  loading?: boolean;
}

export function MCPToolExplorer({ servers, onToolSelect, loading }: MCPToolExplorerProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedServer, setSelectedServer] = useState<string | null>(null);
  const [selectedTool, setSelectedTool] = useState<ToolSchema | null>(null);
  const [showDetail, setShowDetail] = useState(false);

  // Extract all tools from all servers
  const allTools: Array<{ tool: ToolSchema; server: MCPServer }> = useMemo(() => {
    const result: Array<{ tool: ToolSchema; server: MCPServer }> = [];
    
    servers.forEach(server => {
      if (Array.isArray(server.tools)) {
        server.tools.forEach(tool => {
          const toolSchema: ToolSchema = {
            name: typeof tool === 'string' ? tool : (tool as any).name,
            description: typeof tool === 'string' ? '' : (tool as any).description || '',
            inputSchema: typeof tool === 'string' ? undefined : (tool as any).inputSchema,
          };
          result.push({ tool: toolSchema, server });
        });
      }
    });
    
    return result;
  }, [servers]);

  // Filter tools based on search and server filter
  const filteredTools = useMemo(() => {
    return allTools.filter(({ tool, server }) => {
      const matchesSearch = 
        tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        tool.description.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesServer = !selectedServer || server.name === selectedServer;
      
      return matchesSearch && matchesServer;
    });
  }, [allTools, searchQuery, selectedServer]);

  // Group tools by server for display
  const toolsByServer = useMemo(() => {
    const grouped: Record<string, Array<{ tool: ToolSchema; server: MCPServer }>> = {};
    
    filteredTools.forEach(({ tool, server }) => {
      if (!grouped[server.name]) {
        grouped[server.name] = [];
      }
      grouped[server.name].push({ tool, server });
    });
    
    return grouped;
  }, [filteredTools]);

  const handleToolClick = (tool: ToolSchema, server: MCPServer) => {
    setSelectedTool(tool);
    setShowDetail(true);
    if (onToolSelect) {
      onToolSelect(tool, server);
    }
  };

  const serverNames = useMemo(() => {
    return Array.from(new Set(servers.map(s => s.name)));
  }, [servers]);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 260px) 1fr', gap: '1rem', height: '100%' }}>
      {/* Left Sidebar - Filters */}
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem', border: '1px solid var(--border)' }}>
        <div>
          <h3 style={{ fontSize: '0.75rem', fontWeight: 700, marginBottom: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.06em' }}>
            <Filter size={14} style={{ display: 'inline', marginRight: '0.5rem', verticalAlign: 'middle' }} />
            Filter by MCP
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <button
              onClick={() => setSelectedServer(null)}
              style={{
                padding: '0.5rem 0.75rem',
                borderRadius: 'var(--radius-sm)',
                border: selectedServer === null ? '2px solid var(--cyan)' : '1px solid var(--border)',
                background: selectedServer === null ? 'var(--cyan-glow)' : 'transparent',
                color: selectedServer === null ? 'var(--cyan)' : 'var(--text-secondary)',
                cursor: 'pointer',
                textAlign: 'left',
                fontSize: '0.75rem',
                fontWeight: 600,
                transition: 'all 0.2s',
              }}
            >
              All Tools ({allTools.length})
            </button>
            {serverNames.map(name => {
              const toolCount = allTools.filter(t => t.server.name === name).length;
              return (
                <button
                  key={name}
                  onClick={() => setSelectedServer(name)}
                  style={{
                    padding: '0.5rem 0.75rem',
                    borderRadius: 'var(--radius-sm)',
                    border: selectedServer === name ? '2px solid var(--cyan)' : '1px solid var(--border)',
                    background: selectedServer === name ? 'var(--cyan-glow)' : 'transparent',
                    color: selectedServer === name ? 'var(--cyan)' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    textAlign: 'left',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    transition: 'all 0.2s',
                  }}
                >
                  {name} ({toolCount})
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Right Content - Tools List */}
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem', border: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
          <div>
            <h3 style={{ fontSize: '0.875rem', fontWeight: 700 }}>Tool Explorer</h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{filteredTools.length} tools available</p>
          </div>
          {selectedServer && (
            <span style={{ fontSize: '0.6875rem', color: 'var(--cyan)', border: '1px solid var(--border-glow)', background: 'var(--cyan-glow)', borderRadius: 999, padding: '0.2rem 0.55rem' }}>
              Filter: {selectedServer}
            </span>
          )}
        </div>

        {/* Search Bar */}
        <div style={{ position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search tools..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input"
            style={{ paddingLeft: '2.25rem' }}
            onFocus={(e) => (e.currentTarget.style.borderColor = 'var(--cyan)')}
            onBlur={(e) => (e.currentTarget.style.borderColor = 'var(--border)')}
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              style={{
                position: 'absolute',
                right: '0.75rem',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: '0.25rem',
              }}
            >
              <X size={16} />
            </button>
          )}
        </div>

        {/* Tools Grid */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            <div className="animate-spin" style={{ display: 'inline-block' }}>⚙️</div>
            <p style={{ marginTop: '0.5rem', fontSize: '0.875rem' }}>Loading tools...</p>
          </div>
        ) : filteredTools.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            <p style={{ fontSize: '0.875rem' }}>No tools found</p>
            {searchQuery && (
              <p style={{ fontSize: '0.8125rem', marginTop: '0.5rem' }}>Try adjusting your search or filters</p>
            )}
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem' }}>
            {filteredTools.map(({ tool, server }, idx) => (
              <div
                key={`${server.name}-${tool.name}-${idx}`}
                className="card"
                onClick={() => handleToolClick(tool, server)}
                style={{
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  borderLeft: '3px solid transparent',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                }}
                onMouseEnter={(e) => {
                  const el = e.currentTarget as HTMLElement;
                  el.style.borderLeftColor = 'var(--cyan)';
                  el.style.transform = 'translateY(-2px)';
                }}
                onMouseLeave={(e) => {
                  const el = e.currentTarget as HTMLElement;
                  el.style.borderLeftColor = 'transparent';
                  el.style.transform = 'translateY(0)';
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ flex: 1 }}>
                    <h3 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.25rem' }}>
                      {tool.name}
                    </h3>
                    <p style={{
                      fontSize: '0.75rem',
                      color: 'var(--text-muted)',
                      marginBottom: '0.75rem',
                      fontFamily: 'var(--font-mono)',
                    }}>
                      {server.name}
                    </p>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                      {tool.description || 'No description available'}
                    </p>
                  </div>
                  <ChevronRight size={16} style={{ color: 'var(--text-muted)', marginLeft: '0.5rem', flexShrink: 0 }} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
