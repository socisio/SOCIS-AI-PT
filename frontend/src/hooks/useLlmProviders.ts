import { useEffect, useState, useCallback } from 'react';
import { fetchLlmOptions, type LLMProviderOption } from '@/components/LLMProviderSelector';
import { normalizeProvider } from '@/lib/providers';

/**
 * Shared "which provider and model should this feature use" state + data-fetching, extracted from the working logic
 * already in ai-chat/page.tsx — not reinvented. Deliberately holds ONLY the generic parts (the list of
 * admin-configured providers, the currently selected provider/model, a loading flag, and a refresh function).
 *
 * It does NOT bake in chat-specific side effects (saving the choice as the user's persistent chat default, logging
 * a chat-activity line) — those stay in ai-chat/page.tsx's own handleProviderChange. A Findings "analyze this one
 * finding" choice or a Workflow node's per-node provider config must NOT silently overwrite the user's saved chat
 * default; each caller decides what, if anything, to persist.
 */
export function useLlmProviders(initialProvider: string = 'ollama_remote', initialModel: string = '') {
  const [provider, setProvider] = useState<string>(normalizeProvider(initialProvider));
  const [model, setModel] = useState<string>(initialModel);
  const [providers, setProviders] = useState<LLMProviderOption[]>([]);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(() => {
    setLoading(true);
    return fetchLlmOptions()
      .then((opts) => {
        setProviders(opts);
        return opts;
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // When the provider changes, the model list for it is whatever that provider option reports; if the currently
  // selected model isn't in that provider's list anymore (e.g. switching from Ollama to OpenAI), fall back to that
  // provider's own default_model rather than leaving a stale/invalid model string selected silently.
  const current = providers.find((p: LLMProviderOption) => normalizeProvider(p.id) === provider);
  const modelsForProvider = current?.models ?? [];

  const selectProvider = useCallback((id: string) => {
    const normalized = normalizeProvider(id);
    setProvider(normalized);
    const match = providers.find((p: LLMProviderOption) => normalizeProvider(p.id) === normalized);
    setModel(match?.default_model || (match?.models?.[0] ?? ''));
  }, [providers]);

  return {
    provider,
    model,
    setModel,
    selectProvider,
    providers,
    modelsForProvider,
    loading,
    refresh,
  };
}
