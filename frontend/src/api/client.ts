/**
 * Cliente HTTP da API.
 *
 * A chave fica em `sessionStorage`, não em `localStorage`: some ao fechar a aba,
 * o que é o comportamento certo para credencial de console de segurança em
 * máquina possivelmente compartilhada.
 *
 * Nunca vai na query string — só no header. Chave em URL vaza para log de proxy,
 * histórico do navegador e cabeçalho Referer.
 */

import type {
  ModelStatus,
  PipelineHealth,
  Stats,
  ThreatDetail,
  ThreatFilters,
  ThreatPage,
} from './types';

const API_BASE = '/api';
const KEY_STORAGE = 'threat-detector-api-key';

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export function getApiKey(): string | null {
  return sessionStorage.getItem(KEY_STORAGE);
}

export function setApiKey(key: string): void {
  sessionStorage.setItem(KEY_STORAGE, key);
}

export function clearApiKey(): void {
  sessionStorage.removeItem(KEY_STORAGE);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const key = getApiKey();
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (key) headers.set('X-API-Key', key);
  if (init.body) headers.set('Content-Type', 'application/json');

  const response = await fetch(`${API_BASE}${path}`, { ...init, headers });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // Resposta sem corpo JSON; o statusText já serve.
    }
    throw new ApiError(detail, response.status);
  }

  return (await response.json()) as T;
}

function buildQuery(params: Record<string, unknown>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) {
      for (const item of value) search.append(key, String(item));
    } else {
      search.set(key, String(value));
    }
  }
  const query = search.toString();
  return query ? `?${query}` : '';
}

export const api = {
  health: () => request<{ status: string }>('/health'),

  stats: (hours = 24) => request<Stats>(`/stats${buildQuery({ hours })}`),

  pipeline: () => request<PipelineHealth>('/stats/pipeline'),

  threats: (filters: ThreatFilters = {}, cursor?: string, limit = 50) =>
    request<ThreatPage>(`/threats${buildQuery({ ...filters, cursor, limit })}`),

  threat: (id: number) => request<ThreatDetail>(`/threats/${id}`),

  similar: (id: number) => request<ThreatDetail[]>(`/threats/${id}/similar`),

  review: (id: number, isAttack: boolean) =>
    request<ThreatDetail>(`/threats/${id}/review`, {
      method: 'PATCH',
      body: JSON.stringify({ is_attack: isAttack }),
    }),

  models: () => request<ModelStatus>('/models/status'),

  featureNames: () => request<{ count: number; names: string[] }>('/models/features'),

  retrain: (useRealData = true) =>
    request<{ job_id: string; status: string; message: string }>('/models/retrain', {
      method: 'POST',
      body: JSON.stringify({ use_real_data: useRealData }),
    }),
};
