/**
 * Espelha os schemas Pydantic de `backend/app/api/schemas.py`.
 *
 * Escrito à mão de propósito: gerar do OpenAPI acrescentaria uma etapa de build e
 * uma dependência para uma superfície pequena e estável. O teste
 * `test_openapi_is_complete` no backend guarda os caminhos; se um campo mudar
 * aqui sem mudar lá, o `tsc` acusa no primeiro uso.
 */

export type Severity = 'HIGH' | 'MEDIUM' | 'LOW';

export interface RuleMatch {
  rule_id: string;
  category: string;
  severity: string;
  score: number;
  description: string;
  matched_on: string;
}

export interface ThreatSummary {
  id: number;
  ts: string;
  remote_addr: string;
  method: string;
  path: string;
  status: number;
  country: string | null;
  threat_score: number;
  severity: Severity;
  categories: string[];
  reviewed: boolean;
  review_label: boolean | null;
}

export interface ThreatDetail extends ThreatSummary {
  ingested_at: string;
  query: string | null;
  protocol: string;
  bytes_sent: number;
  referer: string | null;
  user_agent: string | null;
  asn: number | null;
  rule_score: number;
  ml_score: number;
  matched_rules: RuleMatch[];
  model_version: string | null;
  reviewed_at: string | null;
}

export interface ThreatPage {
  items: ThreatSummary[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface Stats {
  total_events: number;
  events_last_24h: number;
  unique_attackers_24h: number;
  by_severity: { severity: Severity; count: number }[];
  by_category: { category: string; count: number }[];
  timeline: { bucket: string; total: number; high: number; medium: number; low: number }[];
  top_attackers: { remote_addr: string; events: number; max_score: number; country: string | null }[];
  pending_review: number;
}

export interface ModelVersion {
  version: string;
  created_at: string;
  is_active: boolean;
  promoted: boolean;
  rejection_reason: string | null;
  metrics: Record<string, number>;
  training_source: string;
  sample_count: number;
}

export interface ModelStatus {
  detection_mode: 'ensemble' | 'rules_only';
  active_version: ModelVersion | null;
  history: ModelVersion[];
  artifacts_present: boolean;
  rule_count: number;
  ensemble_weights: Record<string, number>;
  thresholds: Record<string, number>;
}

export interface Alert {
  id: number | null;
  ts: string;
  remote_addr: string;
  method: string;
  path: string;
  query: string | null;
  status: number;
  country: string | null;
  user_agent: string | null;
  rule_score: number;
  ml_score: number;
  threat_score: number;
  severity: Severity;
  categories: string[];
  matched_rules: RuleMatch[];
  model_version: string | null;
  recommend_block: boolean;
}

export interface PipelineHealth {
  status: 'ok' | 'stale' | 'unavailable';
  queues?: Record<string, { depth: number; enqueued: number; dropped: number }>;
  parse?: Record<string, number>;
  dispatch?: Record<string, number>;
  detection_mode?: string;
  model_version?: string | null;
  message?: string;
}

export interface ThreatFilters {
  severity?: Severity[];
  category?: string;
  remote_addr?: string;
  reviewed?: boolean;
  min_score?: number;
}
