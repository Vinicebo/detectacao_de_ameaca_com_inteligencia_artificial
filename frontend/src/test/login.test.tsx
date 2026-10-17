/**
 * Chave recusada devolve o usuário para o login.
 *
 * Antes, uma chave errada ficava guardada na aba e o dashboard não oferecia como
 * corrigi-la: a tela de login só aparecia quando não havia chave nenhuma, então o
 * usuário só se recuperava fechando a aba.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../App';
import { clearApiKey, getApiKey, setApiKey } from '../api/client';
import { __resetSocketState, useAlertStore } from '../stores/alerts';

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static readonly OPEN = 1;
  static readonly CONNECTING = 0;

  readyState = 0;
  binaryType = 'blob';
  onopen: (() => void) | null = null;
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;

  constructor(readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  send(): void {}

  close(): void {
    this.readyState = 3;
  }
}

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('chave recusada volta para o login', () => {
  beforeEach(() => {
    FakeWebSocket.instances = [];
    vi.stubGlobal('WebSocket', FakeWebSocket);
    __resetSocketState();
    useAlertStore.setState({ alerts: [], connection: 'idle', lastError: null, receivedCount: 0 });
    setApiKey('chave-errada');
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    clearApiKey();
  });

  it('descarta a chave e mostra o login quando a API responde 401', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: 'API key inválida' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );

    renderApp();

    expect(await screen.findByLabelText('API key')).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toContain('API key recusada');
    expect(getApiKey()).toBeNull();
  });

  it('descarta a chave e mostra o login quando o WebSocket recusa a autenticação', async () => {
    // REST fica pendente para o 401 vir só do WebSocket.
    vi.stubGlobal('fetch', vi.fn().mockReturnValue(new Promise(() => {})));

    renderApp();
    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    const socket = FakeWebSocket.instances[0]!;

    act(() => {
      socket.readyState = 1;
      socket.onopen?.();
      const frame = new TextEncoder().encode(
        JSON.stringify({ type: 'auth_error', data: { message: 'API key inválida' } }),
      );
      socket.onmessage?.({ data: frame.buffer } as MessageEvent<ArrayBuffer>);
    });

    expect(await screen.findByLabelText('API key')).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toContain('API key recusada');
    expect(getApiKey()).toBeNull();
  });

  it('sem chave guardada mostra o login sem aviso de erro', () => {
    clearApiKey();
    vi.stubGlobal('fetch', vi.fn().mockReturnValue(new Promise(() => {})));

    renderApp();

    expect(screen.getByLabelText('API key')).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
  });
});
