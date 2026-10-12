'use client';

import { useState, useMemo, useCallback } from 'react';
import { Play, Copy, CheckCircle, AlertCircle, Loader, ChevronDown, ChevronUp } from 'lucide-react';
import { MCPServer, ToolSchema, ToolParameter, ToolExecution } from '@/lib/types';
import { FormFieldBuilder } from './FormFieldBuilder';
import { mcpApi } from '@/lib/api';

// Type definitions for better type safety
type ParameterValue = string | number | boolean | null | undefined;
type ParametersMap = Record<string, ParameterValue>;

interface APIResponse {
  data?: {
    result?: unknown;
    error?: {
      message: string;
    };
  };
  error?: {
    message: string;
  };
}

interface MCPToolExecutorProps {
  tool?: ToolSchema | null;
  server?: MCPServer | null;
  onExecute?: (result: ToolExecution) => void;
}

export function MCPToolExecutor({ tool, server, onExecute }: MCPToolExecutorProps) {
  // All hooks must be called unconditionally (before any early returns)
  const [parameters, setParameters] = useState<ParametersMap>({});
  const [execution, setExecution] = useState<ToolExecution>({
    toolName: tool?.name || '',
    mcpServer: server?.name || '',
    parameters: {},
    status: 'idle',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [copied, setCopied] = useState(false);

  // Parse tool schema into parameters with proper typing
  const toolParameters = useMemo(() => {
    if (!tool?.inputSchema) return [];

    const params: ToolParameter[] = [];
    const schema = tool.inputSchema;
    const required = schema.required || [];

    if (schema.properties && typeof schema.properties === 'object') {
      Object.entries(schema.properties).forEach(([name, propSchema]) => {
        const prop = propSchema as Record<string, unknown>;
        params.push({
          name,
          type: (prop.type as string) || 'string',
          required: required.includes(name),
          description: (prop.description as string) || undefined,
          default: prop.default,
          enum: (prop.enum as string[]) || undefined,
          pattern: (prop.pattern as string) || undefined,
          minLength: (prop.minLength as number) || undefined,
          maxLength: (prop.maxLength as number) || undefined,
          minimum: (prop.minimum as number) || undefined,
          maximum: (prop.maximum as number) || undefined,
        });
      });
    }

    return params;
  }, [tool?.inputSchema]);

  const handleParameterChange = useCallback((name: string, value: ParameterValue) => {
    setParameters(prev => ({ ...prev, [name]: value }));
    // Clear error for this field when user starts typing
    if (errors[name]) {
      setErrors(prev => {
        const newErrors = { ...prev };
        delete newErrors[name];
        return newErrors;
      });
    }
  }, [errors]);

  const validateParameters = useCallback((): boolean => {
    const newErrors: Record<string, string> = {};

    toolParameters.forEach(param => {
      const value = parameters[param.name];

      // Check required fields
      if (param.required && (value === undefined || value === null || value === '')) {
        newErrors[param.name] = 'This field is required';
        return;
      }

      // Only validate non-empty values
      if (value !== undefined && value !== null && value !== '') {
        const strValue = String(value);

        if (param.minLength && strValue.length < param.minLength) {
          newErrors[param.name] = `Minimum length is ${param.minLength}`;
        }
        if (param.maxLength && strValue.length > param.maxLength) {
          newErrors[param.name] = `Maximum length is ${param.maxLength}`;
        }
        if (param.pattern) {
          try {
            if (!new RegExp(param.pattern).test(strValue)) {
              newErrors[param.name] = 'Invalid format';
            }
          } catch (e) {
            newErrors[param.name] = 'Invalid validation pattern';
          }
        }
      }
    });

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  }, [toolParameters, parameters]);

  const handleExecute = useCallback(async () => {
    if (!validateParameters()) {
      return;
    }

    // Guard check (should be true since we early return at render if missing)
    if (!server?.name || !tool?.name) {
      setExecution(prev => ({
        ...prev,
        status: 'error',
        error: 'Server or tool not specified',
      }));
      return;
    }

    const startTime = Date.now();
    setExecution(prev => ({
      ...prev,
      status: 'loading',
      parameters,
      error: undefined,
    }));

    try {
      // Call the MCP tool via backend API
      const response = (await mcpApi.callTool(server.name, {
        tool: tool.name,
        arguments: parameters,
      })) as APIResponse;

      // Extract result — backend wraps in { content: [{ type, text }] }
      let result: unknown;
      const rawResult = response?.data?.result ?? response?.data ?? response;
      if (
        rawResult &&
        typeof rawResult === 'object' &&
        Array.isArray((rawResult as any).content) &&
        (rawResult as any).content.length > 0
      ) {
        const text = (rawResult as any).content[0].text;
        try {
          result = JSON.parse(text);
        } catch {
          result = text;
        }
      } else {
        result = rawResult;
      }

      const duration = Date.now() - startTime;

      const execution: ToolExecution = {
        toolName: tool.name,
        mcpServer: server.name,
        parameters,
        result,
        status: 'success',
        duration,
        timestamp: new Date().toISOString(),
      };

      setExecution(execution);
      if (onExecute) {
        onExecute(execution);
      }
    } catch (err) {
      const duration = Date.now() - startTime;
      
      // Type-safe error extraction
      let errorMessage = 'Tool execution failed';
      if (err instanceof Error) {
        errorMessage = err.message;
      } else if (typeof err === 'object' && err !== null) {
        const apiErr = err as any;
        errorMessage = apiErr?.response?.data?.error?.message || 
                      apiErr?.message || 
                      errorMessage;
      }

      const execution: ToolExecution = {
        toolName: tool.name,
        mcpServer: server.name,
        parameters,
        status: 'error',
        error: errorMessage,
        duration,
        timestamp: new Date().toISOString(),
      };

      setExecution(execution);
      if (onExecute) {
        onExecute(execution);
      }
    }
  }, [validateParameters, parameters, server?.name, tool?.name, onExecute]);

  const copyResultToClipboard = useCallback(async () => {
    if (execution.result !== undefined && execution.result !== null) {
      const text = typeof execution.result === 'string' 
        ? execution.result 
        : JSON.stringify(execution.result, null, 2);
      
      // Try clipboard API first
      if (navigator.clipboard && navigator.clipboard.writeText) {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
          return;
        } catch (e) {
          // Clipboard API failed, fallback to legacy method
        }
      }
      
      // Fallback: create temporary textarea
      try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        textarea.style.top = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (e) {
        console.warn('Failed to copy to clipboard');
      }
    }
  }, [execution.result]);

  // Guard against null/undefined props - after all hooks are defined
  if (!tool || !server) {
    return (
      <div 
        style={{ 
          padding: '2rem', 
          textAlign: 'center', 
          color: 'var(--text-muted)',
          borderRadius: 'var(--radius-md)',
          border: '1px solid var(--border)',
          background: 'var(--bg-secondary)',
        }}
        role="status"
        aria-label="No tool selected"
      >
        <p style={{ fontSize: '0.875rem' }}>Select a tool from the explorer to execute it</p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }} role="region" aria-label={`Tool executor for ${tool.name}`}>
      {/* Tool Header */}
      <div style={{ padding: '1.25rem', background: 'var(--cyan-glow)', border: '1px solid var(--border-glow)', borderRadius: 'var(--radius-md)' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.25rem' }}>
          {tool.name}
        </h2>
        <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', fontFamily: 'var(--font-mono)' }}>
          Server: {server.name}
        </p>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          {tool.description || 'No description available'}
        </p>
      </div>

      {/* Parameters Form */}
      {toolParameters.length > 0 && (
        <div style={{ padding: '1.25rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)' }}>
          <h3 style={{ fontSize: '0.875rem', fontWeight: 700, marginBottom: '1rem' }}>
            Parameters ({toolParameters.length})
          </h3>
          <FormFieldBuilder
            parameters={toolParameters}
            values={parameters}
            onChange={handleParameterChange}
            errors={errors}
          />
        </div>
      )}

      {/* Execute Button */}
      <div style={{ display: 'flex', gap: '0.75rem' }}>
        <button
          onClick={handleExecute}
          disabled={execution.status === 'loading'}
          aria-busy={execution.status === 'loading'}
          aria-label="Execute the selected tool"
          style={{
            flex: 1,
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-sm)',
            border: 'none',
            background: execution.status === 'loading' ? 'var(--bg-hover)' : 'var(--cyan)',
            color: execution.status === 'loading' ? 'var(--text-muted)' : '#000',
            fontWeight: 600,
            cursor: execution.status === 'loading' ? 'default' : 'pointer',
            opacity: execution.status === 'loading' ? 0.7 : 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem',
            fontSize: '0.875rem',
          }}
        >
          {execution.status === 'loading' ? (
            <>
              <Loader size={16} className="animate-spin" aria-hidden="true" />
              Executing...
            </>
          ) : (
            <>
              <Play size={16} aria-hidden="true" />
              Execute Tool
            </>
          )}
        </button>
      </div>

      {/* Results Section */}
      {execution.status !== 'idle' && (
        <div 
          style={{ 
            padding: '1.25rem', 
            border: `1px solid color-mix(in srgb, ${execution.status === 'error' ? 'var(--red)' : 'var(--green)'} 19%, transparent)`,
            background: `color-mix(in srgb, ${execution.status === 'error' ? 'var(--chart-red)' : 'var(--chart-green)'} 6%, transparent)`,
            borderRadius: 'var(--radius-md)',
          }}
          role="status"
          aria-label={`Tool execution ${execution.status}: ${execution.status === 'error' ? execution.error : 'completed'}`}
        >
          {/* Status Header */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
            {execution.status === 'success' && (
              <>
                <CheckCircle size={18} color="var(--green)" aria-hidden="true" />
                <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--green)' }}>
                  ✓ Execution Successful
                </span>
              </>
            )}
            {execution.status === 'error' && (
              <>
                <AlertCircle size={18} color="var(--red)" aria-hidden="true" />
                <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--red)' }}>
                  ✗ Execution Failed
                </span>
              </>
            )}
            {execution.status === 'loading' && (
              <>
                <Loader size={18} className="animate-spin" aria-hidden="true" />
                <span style={{ fontSize: '0.875rem', fontWeight: 600 }}>
                  Executing...
                </span>
              </>
            )}
            {execution.duration !== undefined && (
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                Duration: {(execution.duration / 1000).toFixed(2)}s
              </span>
            )}
          </div>

          {/* Error Message */}
          {execution.status === 'error' && execution.error && (
            <div 
              style={{
                padding: '0.75rem',
                background: 'color-mix(in srgb, var(--red) 13%, transparent)',
                border: '1px solid color-mix(in srgb, var(--red) 19%, transparent)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.875rem',
                color: 'var(--red)',
                marginBottom: '1rem',
                fontFamily: 'var(--font-mono)',
                wordBreak: 'break-word',
              }}
              role="alert"
            >
              {execution.error}
            </div>
          )}

          {/* Result Output */}
          {execution.status === 'success' && execution.result !== undefined && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                <h4 style={{ fontSize: '0.875rem', fontWeight: 600 }}>Result:</h4>
                <button
                  type="button"
                  onClick={(e) => {
                    e.preventDefault();
                    copyResultToClipboard();
                  }}
                  aria-label={copied ? 'Copied to clipboard' : 'Copy result to clipboard'}
                  style={{
                    padding: '0.35rem 0.75rem',
                    borderRadius: 'var(--radius-sm)',
                    border: copied ? '1px solid var(--green)' : '1px solid var(--border)',
                    background: copied ? 'color-mix(in srgb, var(--green) 13%, transparent)' : 'transparent',
                    color: copied ? 'var(--green)' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    fontSize: '0.75rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                    transition: 'all 0.2s ease',
                  }}
                >
                  {copied ? (
                    <>
                      <CheckCircle size={12} aria-hidden="true" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy size={12} aria-hidden="true" />
                      Copy
                    </>
                  )}
                </button>
              </div>
              <pre style={{
                background: 'var(--bg-primary)',
                padding: '0.75rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                overflow: 'auto',
                maxHeight: '300px',
                fontSize: '0.75rem',
                lineHeight: 1.4,
                color: 'var(--text-secondary)',
              }}>
                {typeof execution.result === 'string'
                  ? execution.result
                  : JSON.stringify(execution.result, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Advanced Options */}
      <button
        onClick={() => setShowAdvanced(!showAdvanced)}
        aria-expanded={showAdvanced}
        aria-label="Toggle advanced options"
        style={{
          padding: '0.5rem',
          border: 'none',
          background: 'transparent',
          color: 'var(--text-muted)',
          cursor: 'pointer',
          fontSize: '0.8125rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          marginTop: '0.5rem',
        }}
      >
        {showAdvanced ? <ChevronUp size={14} aria-hidden="true" /> : <ChevronDown size={14} aria-hidden="true" />}
        Advanced Options
      </button>

      {showAdvanced && (
        <div 
          style={{
            padding: '1rem',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            fontSize: '0.8125rem',
            color: 'var(--text-secondary)',
          }}
          role="region"
          aria-label="Advanced tool information"
        >
          <p style={{ marginBottom: '0.5rem' }}>📋 Tool Information:</p>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <p>Server: <code>{server.name}</code></p>
            <p>Tool: <code>{tool.name}</code></p>
            <p>Transport: <code>{server.transport || 'unknown'}</code></p>
            {execution.timestamp && <p>Last execution: {new Date(execution.timestamp).toLocaleString()}</p>}
          </div>
        </div>
      )}
    </div>
  );
}
