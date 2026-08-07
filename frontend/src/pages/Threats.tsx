import { useInfiniteQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { api } from '../api/client';
import type { Severity, ThreatFilters } from '../api/types';
import { ThreatDrawer } from '../components/ThreatDrawer';
import {
  CategoryTags,
  EmptyState,
  ErrorBanner,
  SeverityBadge,
  formatDateTime,
} from '../components/common';

const CATEGORIES = [
  'sqli', 'xss', 'traversal', 'cmdi', 'log4shell', 'ssrf', 'scanner', 'protocol',
];

export function Threats() {
  const [filters, setFilters] = useState<ThreatFilters>({});
  const [selected, setSelected] = useState<number | null>(null);

  // useInfiniteQuery casa com a paginação por cursor da API: o `next_cursor` de
  // uma página é o parâmetro da seguinte, sem OFFSET.
  const { data, error, isLoading, fetchNextPage, hasNextPage, isFetchingNextPage } =
    useInfiniteQuery({
      queryKey: ['threats', filters],
      queryFn: ({ pageParam }) => api.threats(filters, pageParam),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    });

  const items = data?.pages.flatMap((page) => page.items) ?? [];

  function update(patch: Partial<ThreatFilters>) {
    setFilters((current) => {
      const next = { ...current, ...patch };
      for (const key of Object.keys(next) as (keyof ThreatFilters)[]) {
        const value = next[key];
        if (value === undefined || value === '' || (Array.isArray(value) && value.length === 0)) {
          delete next[key];
        }
      }
      return next;
    });
  }

  return (
    <>
      <h1 className="page-title">Eventos</h1>
      <p className="page-subtitle">
        Histórico completo, do mais recente para o mais antigo. Clique numa linha para
        ver as regras que casaram e revisar.
      </p>

      <div className="filters">
        <select
          value={filters.severity?.[0] ?? ''}
          onChange={(event) =>
            update({ severity: event.target.value ? [event.target.value as Severity] : undefined })
          }
          aria-label="Severidade"
        >
          <option value="">Toda severidade</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>

        <select
          value={filters.category ?? ''}
          onChange={(event) => update({ category: event.target.value || undefined })}
          aria-label="Categoria"
        >
          <option value="">Toda categoria</option>
          {CATEGORIES.map((category) => (
            <option key={category} value={category}>
              {category}
            </option>
          ))}
        </select>

        <select
          value={filters.reviewed === undefined ? '' : String(filters.reviewed)}
          onChange={(event) =>
            update({ reviewed: event.target.value === '' ? undefined : event.target.value === 'true' })
          }
          aria-label="Revisão"
        >
          <option value="">Revisados e não</option>
          <option value="false">Não revisados</option>
          <option value="true">Revisados</option>
        </select>

        <input
          placeholder="Filtrar por IP"
          value={filters.remote_addr ?? ''}
          onChange={(event) => update({ remote_addr: event.target.value || undefined })}
          aria-label="Endereço de origem"
        />

        {Object.keys(filters).length > 0 && (
          <button onClick={() => setFilters({})}>Limpar filtros</button>
        )}
      </div>

      {error && <ErrorBanner error={error} />}

      <div className="card">
        {isLoading ? (
          <p>Carregando…</p>
        ) : items.length === 0 ? (
          <EmptyState>Nenhum evento encontrado com estes filtros.</EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="threats">
                <thead>
                  <tr>
                    <th>Horário</th>
                    <th>Sev.</th>
                    <th className="score">Escore</th>
                    <th>Origem</th>
                    <th>Requisição</th>
                    <th>Categorias</th>
                    <th>Status</th>
                    <th>Revisão</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr
                      key={item.id}
                      className={selected === item.id ? 'selected' : ''}
                      onClick={() => setSelected(item.id)}
                    >
                      <td className="mono">{formatDateTime(item.ts)}</td>
                      <td>
                        <SeverityBadge severity={item.severity} />
                      </td>
                      <td className="score mono">{item.threat_score.toFixed(2)}</td>
                      <td className="mono">
                        {item.remote_addr}
                        {item.country ? ` ${item.country}` : ''}
                      </td>
                      <td className="path">
                        {item.method} {item.path}
                      </td>
                      <td>
                        <CategoryTags categories={item.categories} />
                      </td>
                      <td className="mono">{item.status}</td>
                      <td>
                        {!item.reviewed ? (
                          <span style={{ color: 'var(--text-faint)' }}>—</span>
                        ) : item.review_label ? (
                          <span style={{ color: 'var(--high)' }}>ataque</span>
                        ) : (
                          <span style={{ color: 'var(--low)' }}>falso pos.</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {hasNextPage && (
              <div style={{ textAlign: 'center', marginTop: 14 }}>
                <button onClick={() => void fetchNextPage()} disabled={isFetchingNextPage}>
                  {isFetchingNextPage ? 'Carregando…' : 'Carregar mais'}
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {selected !== null && (
        <ThreatDrawer id={selected} onClose={() => setSelected(null)} />
      )}
    </>
  );
}
