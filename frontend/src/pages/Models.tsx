import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { api } from '../api/client';
import { ErrorBanner, formatDateTime } from '../components/common';

function metric(value: number | undefined): string {
  return value === undefined ? '—' : value.toFixed(4);
}

export function Models() {
  const queryClient = useQueryClient();
  const [message, setMessage] = useState<string | null>(null);

  const { data, error, isLoading } = useQuery({
    queryKey: ['models'],
    queryFn: () => api.models(),
    // Durante um retreino a versão nova aparece aqui — o polling é o que dá o
    // progresso, já que o job roda em segundo plano.
    refetchInterval: 15_000,
  });

  const retrain = useMutation({
    mutationFn: () => api.retrain(true),
    onSuccess: (response) => {
      setMessage(response.message);
      void queryClient.invalidateQueries({ queryKey: ['models'] });
    },
  });

  return (
    <>
      <h1 className="page-title">Modelos</h1>
      <p className="page-subtitle">
        Ensemble de três modelos exportados para ONNX. O retreino aprende com os eventos
        deste ambiente — inclusive com o que você marcou como falso positivo.
      </p>

      {error && <ErrorBanner error={error} />}
      {message && <div className="notice">{message}</div>}
      {retrain.error && <ErrorBanner error={retrain.error} />}

      {isLoading && <p>Carregando…</p>}

      {data && (
        <>
          {data.detection_mode === 'rules_only' && (
            <div className="notice">
              Modo somente regras: os artefatos ONNX não foram carregados. A detecção
              por assinatura continua funcionando, mas não há detecção de anomalia.
            </div>
          )}

          <div className="stat-grid">
            <div className="stat">
              <div className="value" style={{ fontSize: 18 }}>
                {data.detection_mode === 'ensemble' ? 'Ensemble' : 'Somente regras'}
              </div>
              <div className="label">Modo de detecção</div>
            </div>
            <div className="stat">
              <div className="value">{data.rule_count}</div>
              <div className="label">Regras carregadas</div>
            </div>
            <div className="stat">
              <div className="value">{metric(data.active_version?.metrics.f1)}</div>
              <div className="label">F1 da versão ativa</div>
            </div>
            <div className="stat">
              <div className="value">{metric(data.active_version?.metrics.pr_auc)}</div>
              <div className="label">PR-AUC</div>
            </div>
          </div>

          <div className="grid-2" style={{ marginBottom: 12 }}>
            <div className="card">
              <h3>Versão ativa</h3>
              {data.active_version ? (
                <dl style={{ display: 'grid', gridTemplateColumns: '150px 1fr', gap: '5px 12px', margin: 0, fontSize: 13 }}>
                  <dt style={{ color: 'var(--text-muted)' }}>Versão</dt>
                  <dd className="mono" style={{ margin: 0 }}>{data.active_version.version}</dd>
                  <dt style={{ color: 'var(--text-muted)' }}>Treinada em</dt>
                  <dd style={{ margin: 0 }}>{formatDateTime(data.active_version.created_at)}</dd>
                  <dt style={{ color: 'var(--text-muted)' }}>Origem dos dados</dt>
                  <dd style={{ margin: 0 }}>{data.active_version.training_source}</dd>
                  <dt style={{ color: 'var(--text-muted)' }}>Amostras</dt>
                  <dd style={{ margin: 0 }}>{data.active_version.sample_count.toLocaleString('pt-BR')}</dd>
                  <dt style={{ color: 'var(--text-muted)' }}>Precisão</dt>
                  <dd style={{ margin: 0 }}>{metric(data.active_version.metrics.precision)}</dd>
                  <dt style={{ color: 'var(--text-muted)' }}>Recall</dt>
                  <dd style={{ margin: 0 }}>{metric(data.active_version.metrics.recall)}</dd>
                  <dt style={{ color: 'var(--text-muted)' }}>Falso positivo</dt>
                  <dd style={{ margin: 0 }}>{metric(data.active_version.metrics.false_positive_rate)}</dd>
                </dl>
              ) : (
                <p style={{ color: 'var(--text-muted)' }}>Nenhuma versão promovida ainda.</p>
              )}
            </div>

            <div className="card">
              <h3>Configuração</h3>
              <div style={{ fontSize: 13 }}>
                <p style={{ marginTop: 0, color: 'var(--text-muted)' }}>Pesos do ensemble</p>
                {Object.entries(data.ensemble_weights).map(([name, weight]) => (
                  <div key={name} className="bar-row">
                    <span className="mono">{name}</span>
                    <div className="bar-track">
                      <div className="bar-fill" style={{ width: `${weight * 100}%`, background: 'var(--accent)' }} />
                    </div>
                    <span className="bar-value">{(weight * 100).toFixed(0)}%</span>
                  </div>
                ))}
                <p style={{ marginBottom: 4, color: 'var(--text-muted)' }}>Limiares</p>
                <div className="mono" style={{ fontSize: 12 }}>
                  HIGH ≥ {data.thresholds.high} · MEDIUM ≥ {data.thresholds.medium}
                  <br />
                  portões: F1 ≥ {data.thresholds.min_f1} · PR-AUC ≥ {data.thresholds.min_pr_auc}
                </div>
              </div>
            </div>
          </div>

          <div className="card" style={{ marginBottom: 12 }}>
            <h3>Retreino</h3>
            <p style={{ marginTop: 0, fontSize: 13, color: 'var(--text-muted)' }}>
              Treina com os eventos armazenados: os revisados entram com o rótulo humano,
              os não revisados só nos extremos de escore. Se faltar volume de alguma
              classe, completa com dados sintéticos e registra isso na versão. O modelo
              novo só é promovido se passar nos portões de qualidade — caso contrário a
              versão atual continua ativa e o motivo fica registrado.
            </p>
            <button
              className="primary"
              onClick={() => retrain.mutate()}
              disabled={retrain.isPending}
            >
              {retrain.isPending ? 'Iniciando…' : 'Retreinar agora'}
            </button>
          </div>

          <div className="card">
            <h3>Histórico</h3>
            <div className="table-wrap">
              <table className="threats">
                <thead>
                  <tr>
                    <th>Versão</th>
                    <th>Quando</th>
                    <th>Origem</th>
                    <th className="score">Amostras</th>
                    <th className="score">F1</th>
                    <th className="score">PR-AUC</th>
                    <th>Resultado</th>
                  </tr>
                </thead>
                <tbody>
                  {data.history.map((version) => (
                    <tr key={version.version} style={{ cursor: 'default' }}>
                      <td className="mono">{version.version}</td>
                      <td>{formatDateTime(version.created_at)}</td>
                      <td>{version.training_source}</td>
                      <td className="score">{version.sample_count.toLocaleString('pt-BR')}</td>
                      <td className="score mono">{metric(version.metrics.f1)}</td>
                      <td className="score mono">{metric(version.metrics.pr_auc)}</td>
                      <td>
                        {version.is_active ? (
                          <span className="severity LOW">ATIVA</span>
                        ) : version.promoted ? (
                          <span style={{ color: 'var(--text-muted)' }}>substituída</span>
                        ) : (
                          <span style={{ color: 'var(--high)' }} title={version.rejection_reason ?? ''}>
                            reprovada
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}
