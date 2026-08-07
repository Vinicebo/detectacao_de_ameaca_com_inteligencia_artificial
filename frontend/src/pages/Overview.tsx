import { useQuery } from '@tanstack/react-query';

import { api } from '../api/client';
import { BarList, ErrorBanner } from '../components/common';

function severityCount(
  data: { severity: string; count: number }[] | undefined,
  severity: string,
): number {
  return data?.find((item) => item.severity === severity)?.count ?? 0;
}

/** Barras empilhadas por hora. SVG seria mais bonito; divs bastam e não trazem dependência. */
function Timeline({ buckets }: { buckets: { bucket: string; high: number; medium: number; low: number }[] }) {
  const max = Math.max(...buckets.map((b) => b.high + b.medium + b.low), 1);

  if (buckets.length === 0) {
    return <p style={{ color: 'var(--text-muted)' }}>Sem eventos na janela.</p>;
  }

  return (
    <div className="timeline">
      {buckets.map((bucket) => (
        <div
          className="tl-col"
          key={bucket.bucket}
          title={`${new Date(bucket.bucket).toLocaleString('pt-BR')} — HIGH ${bucket.high}, MEDIUM ${bucket.medium}, LOW ${bucket.low}`}
        >
          <div className="tl-seg tl-low" style={{ height: `${(bucket.low / max) * 100}%` }} />
          <div className="tl-seg tl-medium" style={{ height: `${(bucket.medium / max) * 100}%` }} />
          <div className="tl-seg tl-high" style={{ height: `${(bucket.high / max) * 100}%` }} />
        </div>
      ))}
    </div>
  );
}

export function Overview() {
  const { data, error, isLoading } = useQuery({
    queryKey: ['stats'],
    queryFn: () => api.stats(24),
    refetchInterval: 20_000,
  });

  const { data: pipeline } = useQuery({
    queryKey: ['pipeline'],
    queryFn: () => api.pipeline(),
    refetchInterval: 10_000,
  });

  return (
    <>
      <h1 className="page-title">Visão geral</h1>
      <p className="page-subtitle">Últimas 24 horas de tráfego analisado.</p>

      {error && <ErrorBanner error={error} />}

      {pipeline?.status === 'stale' && (
        <div className="notice">
          O processo detector não publica estatísticas há mais de 30 segundos. Os números
          abaixo continuam válidos (vêm do banco), mas a ingestão pode estar parada.
        </div>
      )}

      {isLoading && <p>Carregando…</p>}

      {data && (
        <>
          <div className="stat-grid">
            <div className="stat high">
              <div className="value">{severityCount(data.by_severity, 'HIGH')}</div>
              <div className="label">Ameaças graves</div>
            </div>
            <div className="stat medium">
              <div className="value">{severityCount(data.by_severity, 'MEDIUM')}</div>
              <div className="label">Ameaças médias</div>
            </div>
            <div className="stat">
              <div className="value">{data.unique_attackers_24h}</div>
              <div className="label">Origens distintas</div>
            </div>
            <div className="stat">
              <div className="value">{data.events_last_24h.toLocaleString('pt-BR')}</div>
              <div className="label">Eventos em 24h</div>
            </div>
            <div className="stat">
              <div className="value">{data.pending_review}</div>
              <div className="label">Aguardando revisão</div>
            </div>
          </div>

          <div className="card" style={{ marginBottom: 12 }}>
            <h3>Linha do tempo por hora</h3>
            <Timeline buckets={data.timeline} />
          </div>

          <div className="grid-2">
            <div className="card">
              <h3>Categorias de ataque</h3>
              {data.by_category.length === 0 ? (
                <p style={{ color: 'var(--text-muted)' }}>Nenhum ataque categorizado ainda.</p>
              ) : (
                <BarList
                  items={data.by_category.map((c) => ({ label: c.category, value: c.count }))}
                  color="var(--high)"
                />
              )}
            </div>

            <div className="card">
              <h3>Origens mais ativas</h3>
              {data.top_attackers.length === 0 ? (
                <p style={{ color: 'var(--text-muted)' }}>Nenhuma origem suspeita ainda.</p>
              ) : (
                <BarList
                  items={data.top_attackers.map((a) => ({
                    label: `${a.remote_addr}${a.country ? ` ${a.country}` : ''}`,
                    value: a.events,
                  }))}
                  color="var(--medium)"
                />
              )}
            </div>
          </div>

          {pipeline?.status === 'ok' && pipeline.queues && (
            <div className="card" style={{ marginTop: 12 }}>
              <h3>Saúde do pipeline</h3>
              <div className="grid-2">
                <div>
                  {Object.entries(pipeline.queues).map(([name, queue]) => (
                    <div key={name} style={{ fontSize: 13, marginBottom: 4 }}>
                      <span className="mono">{name}</span>{' '}
                      <span style={{ color: 'var(--text-muted)' }}>
                        fila {queue.depth} · processados {queue.enqueued}
                      </span>{' '}
                      {queue.dropped > 0 && (
                        <span style={{ color: 'var(--high)' }}>· {queue.dropped} descartados</span>
                      )}
                    </div>
                  ))}
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                  <div>modo: {pipeline.detection_mode}</div>
                  <div>modelo: {pipeline.model_version ?? '—'}</div>
                  <div>linhas lidas: {pipeline.parse?.parsed ?? 0}</div>
                  <div>malformadas: {pipeline.parse?.malformed ?? 0}</div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </>
  );
}
