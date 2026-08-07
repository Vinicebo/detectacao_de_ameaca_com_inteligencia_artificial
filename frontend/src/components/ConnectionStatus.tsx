import { useAlertStore } from '../stores/alerts';

const LABELS: Record<string, string> = {
  idle: 'desconectado',
  connecting: 'conectando',
  authenticating: 'autenticando',
  live: 'ao vivo',
  reconnecting: 'reconectando',
  failed: 'falhou',
};

/**
 * Estado da conexão do feed.
 *
 * Visível o tempo todo, e não só quando quebra: um dashboard silencioso é
 * ambíguo — pode significar "nenhum ataque" ou "o feed caiu". A diferença entre
 * as duas coisas é enorme, e sem este indicador não há como saber qual é.
 */
export function ConnectionStatus() {
  const connection = useAlertStore((state) => state.connection);
  const lastError = useAlertStore((state) => state.lastError);
  const received = useAlertStore((state) => state.receivedCount);

  return (
    <div className={`conn ${connection}`} title={lastError ?? undefined}>
      <span className="dot" />
      <span>
        {LABELS[connection] ?? connection}
        {connection === 'live' && received > 0 && ` · ${received}`}
      </span>
    </div>
  );
}
