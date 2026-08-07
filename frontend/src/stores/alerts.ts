/**
 * Estado do feed de alertas em tempo real.
 *
 * Zustand e não TanStack Query porque isto é um fluxo empurrado pelo servidor, não
 * um recurso que se busca e revalida.
 *
 * Três decisões que importam:
 *
 * 1. **Buffer limitado.** Um dashboard aberto a noite toda durante um flood
 *    acumularia centenas de milhares de alertas e travaria a aba. Guardamos os
 *    500 mais recentes; o histórico completo está no Postgres.
 * 2. **Reconexão com backoff exponencial.** Se a API reinicia, dez abas abertas
 *    tentando reconectar a cada segundo viram um ataque de negação de serviço
 *    contra o próprio sistema.
 * 3. **Autenticação por frame.** A chave vai no primeiro frame após o handshake,
 *    nunca na URL — o servidor exige isso em até 5 segundos.
 */

import { create } from 'zustand';
import { getApiKey } from '../api/client';
import type { Alert } from '../api/types';

const MAX_BUFFERED_ALERTS = 500;
const BASE_RECONNECT_DELAY_MS = 1000;
const MAX_RECONNECT_DELAY_MS = 30000;

export type ConnectionState = 'idle' | 'connecting' | 'authenticating' | 'live' | 'reconnecting' | 'failed';

interface AlertState {
  alerts: Alert[];
  connection: ConnectionState;
  lastError: string | null;
  receivedCount: number;
  connect: () => void;
  disconnect: () => void;
  clear: () => void;
}

let socket: WebSocket | null = null;
let reconnectTimer: number | null = null;
let attempt = 0;
let intentionallyClosed = false;

function socketUrl(): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/ws/alerts`;
}

function reconnectDelay(): number {
  // 1s, 2s, 4s, 8s… até o teto. O jitter evita que várias abas reconectem no
  // mesmo instante e batam todas juntas na API que acabou de subir.
  const backoff = Math.min(BASE_RECONNECT_DELAY_MS * 2 ** attempt, MAX_RECONNECT_DELAY_MS);
  return backoff + Math.random() * 500;
}

export const useAlertStore = create<AlertState>((set, get) => ({
  alerts: [],
  connection: 'idle',
  lastError: null,
  receivedCount: 0,

  connect: () => {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const key = getApiKey();
    if (!key) {
      set({ connection: 'failed', lastError: 'API key não configurada' });
      return;
    }

    intentionallyClosed = false;
    set({ connection: 'connecting', lastError: null });

    socket = new WebSocket(socketUrl());

    socket.onopen = () => {
      set({ connection: 'authenticating' });
      socket?.send(JSON.stringify({ type: 'auth', api_key: key }));
    };

    socket.onmessage = (event: MessageEvent<string>) => {
      let message: { type: string; data: unknown };
      try {
        message = JSON.parse(event.data) as { type: string; data: unknown };
      } catch {
        return;
      }

      switch (message.type) {
        case 'auth_ok':
          attempt = 0; // conexão boa: zera o backoff
          set({ connection: 'live', lastError: null });
          break;

        case 'auth_error':
          set({
            connection: 'failed',
            lastError: (message.data as { message?: string })?.message ?? 'falha na autenticação',
          });
          intentionallyClosed = true; // chave errada não melhora com retentativa
          break;

        case 'snapshot': {
          const snapshot = (message.data as Alert[]) ?? [];
          set({ alerts: snapshot.slice(0, MAX_BUFFERED_ALERTS) });
          break;
        }

        case 'alert': {
          const alert = message.data as Alert;
          set((state) => ({
            alerts: [alert, ...state.alerts].slice(0, MAX_BUFFERED_ALERTS),
            receivedCount: state.receivedCount + 1,
          }));
          break;
        }

        case 'pong':
          break;
      }
    };

    socket.onerror = () => {
      set({ lastError: 'erro de conexão' });
    };

    socket.onclose = (event: CloseEvent) => {
      socket = null;
      if (intentionallyClosed) {
        set({ connection: get().connection === 'failed' ? 'failed' : 'idle' });
        return;
      }

      set({
        connection: 'reconnecting',
        lastError: event.reason || `conexão encerrada (${event.code})`,
      });

      // Calcula com a contagem atual e só então incrementa: assim a primeira
      // retentativa espera ~1s, como documentado, e não 2s.
      const delay = reconnectDelay();
      attempt += 1;
      reconnectTimer = window.setTimeout(() => get().connect(), delay);
    };
  },

  disconnect: () => {
    intentionallyClosed = true;
    if (reconnectTimer !== null) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    socket?.close();
    socket = null;
    attempt = 0;
    set({ connection: 'idle' });
  },

  clear: () => set({ alerts: [], receivedCount: 0 }),
}));

/** Exposto para teste — reinicia o estado do módulo entre casos. */
export function __resetSocketState(): void {
  socket = null;
  attempt = 0;
  intentionallyClosed = false;
  if (reconnectTimer !== null) {
    window.clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}
