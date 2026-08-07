import { useState } from 'react';

import type { Severity } from '../api/types';
import { ThreatDrawer } from '../components/ThreatDrawer';
import { CategoryTags, EmptyState, SeverityBadge, formatTime } from '../components/common';
import { useAlertStore } from '../stores/alerts';

export function LiveFeed() {
  const alerts = useAlertStore((state) => state.alerts);
  const connection = useAlertStore((state) => state.connection);
  const lastError = useAlertStore((state) => state.lastError);
  const clear = useAlertStore((state) => state.clear);

  const [minSeverity, setMinSeverity] = useState<Severity | 'ALL'>('ALL');
  const [selected, setSelected] = useState<number | null>(null);

  const visible = alerts.filter(
    (alert) => minSeverity === 'ALL' || alert.severity === minSeverity,
  );

  return (
    <>
      <h1 className="page-title">Ao vivo</h1>
      <p className="page-subtitle">
        Alertas conforme chegam. O histórico completo fica em Eventos — aqui só os
        500 mais recentes, para a aba não crescer sem limite durante um flood.
      </p>

      {connection === 'failed' && (
        <div className="error-banner">
          Feed desconectado: {lastError ?? 'motivo desconhecido'}
        </div>
      )}
      {connection === 'reconnecting' && (
        <div className="notice">
          Reconectando com espera progressiva… Os eventos continuam sendo gravados no
          banco enquanto isso; nada se perde.
        </div>
      )}

      <div className="filters">
        <label htmlFor="sev">Severidade</label>
        <select
          id="sev"
          value={minSeverity}
          onChange={(event) => setMinSeverity(event.target.value as Severity | 'ALL')}
        >
          <option value="ALL">Todas</option>
          <option value="HIGH">Apenas HIGH</option>
          <option value="MEDIUM">Apenas MEDIUM</option>
        </select>
        <button onClick={clear}>Limpar</button>
        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>
          {visible.length} exibidos
        </span>
      </div>

      <div className="card">
        {visible.length === 0 ? (
          <EmptyState>
            {connection === 'live'
              ? 'Conectado. Nenhum alerta ainda — gere tráfego com dev-log/simulate.py.'
              : 'Aguardando conexão…'}
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="threats">
              <thead>
                <tr>
                  <th>Hora</th>
                  <th>Sev.</th>
                  <th className="score">Escore</th>
                  <th>Origem</th>
                  <th>Requisição</th>
                  <th>Categorias</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((alert, index) => (
                  <tr
                    key={`${alert.id ?? 'x'}-${alert.ts}-${index}`}
                    onClick={() => alert.id !== null && setSelected(alert.id)}
                  >
                    <td className="mono">{formatTime(alert.ts)}</td>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td className="score mono">{alert.threat_score.toFixed(2)}</td>
                    <td className="mono">
                      {alert.remote_addr}
                      {alert.country ? ` ${alert.country}` : ''}
                    </td>
                    <td className="path">
                      {alert.method} {alert.path}
                      {alert.query ? `?${alert.query}` : ''}
                    </td>
                    <td>
                      <CategoryTags categories={alert.categories} />
                    </td>
                    <td className="mono">{alert.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected !== null && (
        <ThreatDrawer id={selected} onClose={() => setSelected(null)} />
      )}
    </>
  );
}
