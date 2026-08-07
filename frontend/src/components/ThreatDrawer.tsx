import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { api } from '../api/client';
import { CategoryTags, ErrorBanner, SeverityBadge, formatDateTime } from './common';

/**
 * Detalhe do evento.
 *
 * Mostra as regras que casaram *com o trecho exato* e a decomposição do escore.
 * Sem isso o analista não tem como julgar o alerta — e um alerta que não dá para
 * julgar acaba ignorado, o que é pior do que não tê-lo emitido.
 */
export function ThreatDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ['threat', id],
    queryFn: () => api.threat(id),
  });

  const { data: contract } = useQuery({
    queryKey: ['feature-names'],
    queryFn: () => api.featureNames(),
    staleTime: Infinity, // o contrato só muda com retreino
  });

  const review = useMutation({
    mutationFn: (isAttack: boolean) => api.review(id, isAttack),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['threat', id] });
      void queryClient.invalidateQueries({ queryKey: ['threats'] });
      void queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  return (
    <aside className="drawer">
      <div className="drawer-head">
        <div>
          <h2 style={{ margin: 0, fontSize: 16 }}>Evento #{id}</h2>
          {data && (
            <div style={{ marginTop: 6 }}>
              <SeverityBadge severity={data.severity} />{' '}
              <span className="mono">{data.threat_score.toFixed(3)}</span>
            </div>
          )}
        </div>
        <button onClick={onClose} aria-label="Fechar">
          ✕
        </button>
      </div>

      {isLoading && <p>Carregando…</p>}
      {error && <ErrorBanner error={error} />}

      {data && (
        <>
          <dl>
            <dt>Horário</dt>
            <dd>{formatDateTime(data.ts)}</dd>
            <dt>Origem</dt>
            <dd>
              {data.remote_addr}
              {data.country ? ` (${data.country})` : ''}
            </dd>
            <dt>Requisição</dt>
            <dd>
              {data.method} {data.path}
              {data.query ? `?${data.query}` : ''}
            </dd>
            <dt>Resposta</dt>
            <dd>
              {data.status} · {data.bytes_sent} bytes
            </dd>
            <dt>User-Agent</dt>
            <dd>{data.user_agent || '—'}</dd>
            <dt>Referer</dt>
            <dd>{data.referer || '—'}</dd>
            <dt>Categorias</dt>
            <dd>
              <CategoryTags categories={data.categories} />
            </dd>
          </dl>

          <div className="card" style={{ marginBottom: 18 }}>
            <h3>Decomposição do escore</h3>
            <dl style={{ marginBottom: 0 }}>
              <dt>Regras</dt>
              <dd>{data.rule_score.toFixed(3)}</dd>
              <dt>Modelo (ML)</dt>
              <dd>{data.ml_score.toFixed(3)}</dd>
              <dt>Final</dt>
              <dd>{data.threat_score.toFixed(3)}</dd>
              <dt>Versão do modelo</dt>
              <dd>{data.model_version ?? 'somente regras'}</dd>
            </dl>
          </div>

          <h3 style={{ fontSize: 12, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
            Regras que casaram ({data.matched_rules.length})
          </h3>
          {data.matched_rules.length === 0 ? (
            <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
              Nenhuma regra casou — este alerta veio inteiramente do modelo, que
              considerou a requisição anômala em relação ao tráfego normal.
            </p>
          ) : (
            data.matched_rules.map((rule) => (
              <div className="rule-match" key={rule.rule_id}>
                <div className="rule-id">
                  {rule.rule_id} · {rule.category} · {rule.score.toFixed(2)}
                </div>
                <div className="rule-desc">{rule.description}</div>
                <div className="rule-evidence">{rule.matched_on}</div>
              </div>
            ))
          )}

          {contract && data.severity !== 'LOW' && (
            <details style={{ marginTop: 18 }}>
              <summary style={{ cursor: 'pointer', color: 'var(--text-muted)', fontSize: 12 }}>
                Vetor de features ({contract.count} dimensões)
              </summary>
              <div className="feature-grid" style={{ marginTop: 10 }}>
                {contract.names.map((name, index) => {
                  const value = (data as unknown as { features?: number[] }).features?.[index] ?? 0;
                  return (
                    <span key={name} className={`fname ${value === 0 ? 'zero' : ''}`}>
                      {name}
                      <span className="fvalue" style={{ float: 'right' }}>
                        {value.toFixed(3)}
                      </span>
                    </span>
                  );
                })}
              </div>
            </details>
          )}

          <div style={{ display: 'flex', gap: 8, marginTop: 22 }}>
            {data.reviewed ? (
              <div className="notice" style={{ margin: 0, flex: 1 }}>
                Revisado como <strong>{data.review_label ? 'ataque real' : 'falso positivo'}</strong>
                {data.reviewed_at && ` em ${formatDateTime(data.reviewed_at)}`}
              </div>
            ) : (
              <>
                <button
                  className="danger"
                  disabled={review.isPending}
                  onClick={() => review.mutate(true)}
                >
                  Ataque real
                </button>
                <button
                  className="success"
                  disabled={review.isPending}
                  onClick={() => review.mutate(false)}
                >
                  Falso positivo
                </button>
              </>
            )}
          </div>
          <p style={{ color: 'var(--text-faint)', fontSize: 12, marginTop: 10 }}>
            A revisão vira rótulo de treino: é o que faz o próximo retreino aprender
            com julgamento humano em vez de com os próprios palpites do sistema.
          </p>
        </>
      )}
    </aside>
  );
}
