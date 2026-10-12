'use client';

import { ToolParameter } from '@/lib/types';

interface FormFieldBuilderProps {
  parameters: ToolParameter[];
  values: Record<string, any>;
  onChange: (name: string, value: any) => void;
  errors?: Record<string, string>;
}

export function FormFieldBuilder({ parameters, values, onChange, errors = {} }: FormFieldBuilderProps) {
  if (!parameters || parameters.length === 0) {
    return (
      <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
        No parameters required for this tool
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {parameters.map((param) => (
        <div key={param.name} style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {/* Label */}
          <label style={{ fontSize: '0.875rem', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            {param.name}
            {param.required && <span style={{ color: 'var(--red)' }}>*</span>}
          </label>

          {/* Description */}
          {param.description && (
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0 0 0.35rem 0' }}>
              {param.description}
            </p>
          )}

          {/* Input Field - varies by type */}
          {param.type === 'string' ? (
            param.enum ? (
              // Dropdown for enum
              <select
                value={values[param.name] || ''}
                onChange={(e) => onChange(param.name, e.target.value)}
                style={{
                  padding: '0.625rem',
                  borderRadius: 'var(--radius-sm)',
                  border: `1px solid ${errors[param.name] ? 'var(--red)' : 'var(--border)'}`,
                  background: 'var(--bg-primary)',
                  color: 'var(--text-primary)',
                  fontSize: '0.875rem',
                  cursor: 'pointer',
                  outline: 'none',
                  colorScheme: 'dark',
                }}
              >
                <option value="" style={{ background: 'var(--bg-primary)', color: 'var(--text-primary)' }}>Select an option...</option>
                {param.enum.map((option) => (
                  <option key={option} value={option} style={{ background: 'var(--bg-primary)', color: 'var(--text-primary)' }}>
                    {option}
                  </option>
                ))}
              </select>
            ) : (
              // Text input for strings
              <input
                type="text"
                value={values[param.name] || ''}
                onChange={(e) => onChange(param.name, e.target.value)}
                placeholder={param.description || 'Enter value...'}
                style={{
                  padding: '0.625rem',
                  borderRadius: 'var(--radius-sm)',
                  border: `1px solid ${errors[param.name] ? 'var(--red)' : 'var(--border)'}`,
                  background: 'var(--bg)',
                  color: 'var(--text)',
                  fontSize: '0.875rem',
                  outline: 'none',
                }}
                onFocus={(e) => {
                  if (!errors[param.name]) {
                    e.currentTarget.style.borderColor = 'var(--cyan)';
                  }
                }}
                onBlur={(e) => {
                  e.currentTarget.style.borderColor = errors[param.name] ? 'var(--red)' : 'var(--border)';
                }}
              />
            )
          ) : param.type === 'number' ? (
            <input
              type="number"
              value={values[param.name] ?? ''}
              onChange={(e) => onChange(param.name, e.target.value ? parseInt(e.target.value) : '')}
              min={param.minimum}
              max={param.maximum}
              placeholder="Enter number..."
              style={{
                padding: '0.625rem',
                borderRadius: 'var(--radius-sm)',
                border: `1px solid ${errors[param.name] ? 'var(--red)' : 'var(--border)'}`,
                background: 'var(--bg)',
                color: 'var(--text)',
                fontSize: '0.875rem',
                outline: 'none',
              }}
              onFocus={(e) => {
                if (!errors[param.name]) {
                  e.currentTarget.style.borderColor = 'var(--cyan)';
                }
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = errors[param.name] ? 'var(--red)' : 'var(--border)';
              }}
            />
          ) : param.type === 'boolean' ? (
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', cursor: 'pointer', marginTop: '0.25rem' }}>
              <input
                type="checkbox"
                checked={values[param.name] || false}
                onChange={(e) => onChange(param.name, e.target.checked)}
                style={{
                  width: '16px',
                  height: '16px',
                  cursor: 'pointer',
                  accentColor: 'var(--cyan)',
                }}
              />
              <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                {param.description || `Enable ${param.name}`}
              </span>
            </label>
          ) : param.type === 'array' ? (
            <textarea
              value={Array.isArray(values[param.name]) ? JSON.stringify(values[param.name]) : ''}
              onChange={(e) => {
                try {
                  onChange(param.name, JSON.parse(e.target.value));
                } catch {
                  onChange(param.name, e.target.value);
                }
              }}
              placeholder={`Enter JSON array, e.g. ["value1", "value2"]`}
              rows={3}
              style={{
                padding: '0.625rem',
                borderRadius: 'var(--radius-sm)',
                border: `1px solid ${errors[param.name] ? 'var(--red)' : 'var(--border)'}`,
                background: 'var(--bg)',
                color: 'var(--text)',
                fontSize: '0.875rem',
                fontFamily: 'var(--font-mono)',
                outline: 'none',
                resize: 'vertical',
              }}
              onFocus={(e) => {
                if (!errors[param.name]) {
                  e.currentTarget.style.borderColor = 'var(--cyan)';
                }
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = errors[param.name] ? 'var(--red)' : 'var(--border)';
              }}
            />
          ) : param.type === 'object' ? (
            <textarea
              value={typeof values[param.name] === 'object' ? JSON.stringify(values[param.name]) : ''}
              onChange={(e) => {
                try {
                  onChange(param.name, JSON.parse(e.target.value));
                } catch {
                  onChange(param.name, e.target.value);
                }
              }}
              placeholder={`Enter JSON object, e.g. {"key": "value"}`}
              rows={4}
              style={{
                padding: '0.625rem',
                borderRadius: 'var(--radius-sm)',
                border: `1px solid ${errors[param.name] ? 'var(--red)' : 'var(--border)'}`,
                background: 'var(--bg)',
                color: 'var(--text)',
                fontSize: '0.875rem',
                fontFamily: 'var(--font-mono)',
                outline: 'none',
                resize: 'vertical',
              }}
              onFocus={(e) => {
                if (!errors[param.name]) {
                  e.currentTarget.style.borderColor = 'var(--cyan)';
                }
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = errors[param.name] ? 'var(--red)' : 'var(--border)';
              }}
            />
          ) : (
            <input
              type="text"
              value={values[param.name] || ''}
              onChange={(e) => onChange(param.name, e.target.value)}
              placeholder="Enter value..."
              style={{
                padding: '0.625rem',
                borderRadius: 'var(--radius-sm)',
                border: `1px solid ${errors[param.name] ? 'var(--red)' : 'var(--border)'}`,
                background: 'var(--bg)',
                color: 'var(--text)',
                fontSize: '0.875rem',
                outline: 'none',
              }}
              onFocus={(e) => {
                if (!errors[param.name]) {
                  e.currentTarget.style.borderColor = 'var(--cyan)';
                }
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = errors[param.name] ? 'var(--red)' : 'var(--border)';
              }}
            />
          )}

          {/* Constraints */}
          {(param.minLength || param.maxLength || param.pattern) && (
            <p style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              {param.minLength && `Min: ${param.minLength}`}
              {param.maxLength && ` • Max: ${param.maxLength}`}
              {param.pattern && ` • Pattern: ${param.pattern}`}
            </p>
          )}

          {/* Error Message */}
          {errors[param.name] && (
            <p style={{ fontSize: '0.75rem', color: 'var(--red)', marginTop: '0.25rem' }}>
              ❌ {errors[param.name]}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
