import { useEffect, useState } from 'react';
import { NavLink, Route, Routes } from 'react-router-dom';

import { API_KEY_REJECTED_EVENT, getApiKey, setApiKey } from './api/client';
import { ConnectionStatus } from './components/ConnectionStatus';
import { LiveFeed } from './pages/LiveFeed';
import { Models } from './pages/Models';
import { Overview } from './pages/Overview';
import { Threats } from './pages/Threats';
import { useAlertStore } from './stores/alerts';

/** Pede a API key antes de qualquer coisa — sem ela nenhuma rota responde. */
function ApiKeyGate({
  onSubmit,
  rejected,
}: {
  onSubmit: (key: string) => void;
  rejected: boolean;
}) {
  const [value, setValue] = useState('');

  return (
    <div className="gate">
      <h1>
        Detector de <span style={{ color: 'var(--high)' }}>Ameaças</span>
      </h1>
      {rejected && (
        <div className="error-banner" role="alert">
          API key recusada. Confira o valor de <code>API_KEY</code> no <code>.env</code>.
        </div>
      )}
      <p>
        Informe a API key configurada em <code>API_KEY</code> no <code>.env</code>. Ela fica
        guardada apenas nesta aba e é descartada ao fechá-la.
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (value.trim()) onSubmit(value.trim());
        }}
      >
        <input
          type="password"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="API key"
          autoFocus
          aria-label="API key"
        />
        <button type="submit" className="primary">
          Entrar
        </button>
      </form>
    </div>
  );
}

export function App() {
  const [authenticated, setAuthenticated] = useState(() => getApiKey() !== null);
  const [rejected, setRejected] = useState(false);
  const connect = useAlertStore((state) => state.connect);
  const disconnect = useAlertStore((state) => state.disconnect);

  useEffect(() => {
    // A API ou o WebSocket recusaram a chave: ela já foi descartada, então basta
    // voltar para o login, onde o usuário digita a correta.
    const onRejected = () => {
      setRejected(true);
      setAuthenticated(false);
    };
    window.addEventListener(API_KEY_REJECTED_EVENT, onRejected);
    return () => window.removeEventListener(API_KEY_REJECTED_EVENT, onRejected);
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    // Uma conexão para o app inteiro, não uma por página: trocar de aba não pode
    // derrubar e reabrir o feed.
    connect();
    return () => disconnect();
  }, [authenticated, connect, disconnect]);

  if (!authenticated) {
    return (
      <ApiKeyGate
        rejected={rejected}
        onSubmit={(key) => {
          setApiKey(key);
          setRejected(false);
          setAuthenticated(true);
        }}
      />
    );
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          Detector de <span>Ameaças</span>
        </div>
        <nav>
          <NavLink to="/" end>
            Visão geral
          </NavLink>
          <NavLink to="/feed">Ao vivo</NavLink>
          <NavLink to="/threats">Eventos</NavLink>
          <NavLink to="/models">Modelos</NavLink>
        </nav>
        <div className="spacer" />
        <ConnectionStatus />
      </aside>

      <main className="content">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/feed" element={<LiveFeed />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/models" element={<Models />} />
        </Routes>
      </main>
    </div>
  );
}
