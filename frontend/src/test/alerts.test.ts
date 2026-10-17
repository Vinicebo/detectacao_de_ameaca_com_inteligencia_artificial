/**
 * Testes do store do feed em tempo real.
 *
 * O foco é o comportamento que não dá para verificar olhando a tela: o buffer não
 * cresce sem limite, a chave nunca vai para a URL, e a reconexão espera de forma
 * progressiva.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { clearApiKey, getApiKey, setApiKey } from '../api/client';
import type { Alert } from '../api/types';
import { __resetSocketState, useAlertStore } from '../stores/alerts';

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static readonly OPEN = 1;

  readyState = 0;
  binaryType = 'blob';
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;

  constructor(readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    this.readyState = 3;
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.();
  }

  emit(type: string, data: unknown): void {
    this.onmessage?.({ data: JSON.stringify({ type, data }) } as MessageEvent<string>);
  }

  /** O servidor real envia frames binários (`send_bytes`), não texto. */
  emitBinary(type: string, data: unknown): void {
    const bytes = new TextEncoder().encode(JSON.stringify({ type, data }));
    this.onmessage?.({ data: bytes.buffer } as MessageEvent<ArrayBuffer>);
  }
}

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 1,
    ts: '2026-08-06T14:30:00Z',
    remote_addr: '198.51.100.5',
    method: 'GET',
    path: '/produto',
    query: "id=1' OR '1'='1",
    status: 500,
    country: null,
    user_agent: 'sqlmap/1.8',
    rule_score: 0.95,
    ml_score: 0.8,
    threat_score: 0.95,
    severity: 'HIGH',
    categories: ['sqli'],
    matched_rules: [],
    model_version: 'v1',
    recommend_block: true,
    ...overrides,
  };
}

describe('store de alertas', () => {
  beforeEach(() => {
    FakeWebSocket.instances = [];
    vi.stubGlobal('WebSocket', FakeWebSocket);
    __resetSocketState();
    useAlertStore.setState({ alerts: [], connection: 'idle', lastError: null, receivedCount: 0 });
    setApiKey('chave-de-teste');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    clearApiKey();
  });

  it('envia a chave num frame, nunca na URL', () => {
    // Chave em query string vaza para log de proxy, histórico e Referer.
    useAlertStore.getState().connect();
    const socket = FakeWebSocket.instances[0]!;

    expect(socket.url).not.toContain('chave-de-teste');
    expect(socket.url).not.toContain('api_key');

    socket.open();
    expect(JSON.parse(socket.sent[0]!)).toEqual({ type: 'auth', api_key: 'chave-de-teste' });
  });

  it('só entra em live depois do auth_ok', () => {
    useAlertStore.getState().connect();
    const socket = FakeWebSocket.instances[0]!;

    socket.open();
    expect(useAlertStore.getState().connection).toBe('authenticating');

    socket.emit('auth_ok', { heartbeat_seconds: 30 });
    expect(useAlertStore.getState().connection).toBe('live');
  });

  it('entende frames binários, que é como o servidor realmente envia', () => {
    // Regressão: sem `binaryType = 'arraybuffer'` o navegador entrega um Blob, o
    // JSON.parse falha em silêncio e o feed fica preso em "autenticando".
    useAlertStore.getState().connect();
    const socket = FakeWebSocket.instances[0]!;
    expect(socket.binaryType).toBe('arraybuffer');

    socket.open();
    socket.emitBinary('auth_ok', { heartbeat_seconds: 30 });
    expect(useAlertStore.getState().connection).toBe('live');

    socket.emitBinary('alert', makeAlert({ id: 7, path: '/binario' }));
    expect(useAlertStore.getState().alerts[0]?.path).toBe('/binario');
  });

  it('marca falha e não reconecta quando a chave é rejeitada', () => {
    // Retentar com chave errada só produz laço infinito contra a API.
    useAlertStore.getState().connect();
    const socket = FakeWebSocket.instances[0]!;
    socket.open();
    socket.emit('auth_error', { message: 'API key inválida' });

    expect(useAlertStore.getState().connection).toBe('failed');
    // A chave recusada é descartada, para o app poder pedir outra.
    expect(getApiKey()).toBeNull();

    socket.onclose?.({ code: 4003, reason: 'não autorizado' } as CloseEvent);
    expect(useAlertStore.getState().connection).toBe('failed');
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('acrescenta alertas com o mais recente primeiro', () => {
    useAlertStore.getState().connect();
    const socket = FakeWebSocket.instances[0]!;
    socket.open();
    socket.emit('auth_ok', {});

    socket.emit('alert', makeAlert({ id: 1, path: '/primeiro' }));
    socket.emit('alert', makeAlert({ id: 2, path: '/segundo' }));

    const { alerts, receivedCount } = useAlertStore.getState();
    expect(alerts[0]?.path).toBe('/segundo');
    expect(alerts).toHaveLength(2);
    expect(receivedCount).toBe(2);
  });

  it('limita o buffer para a aba não travar num flood', () => {
    // Um dashboard aberto a noite toda durante um flood acumularia centenas de
    // milhares de alertas. O histórico completo está no Postgres.
    useAlertStore.getState().connect();
    const socket = FakeWebSocket.instances[0]!;
    socket.open();
    socket.emit('auth_ok', {});

    for (let index = 0; index < 800; index += 1) {
      socket.emit('alert', makeAlert({ id: index }));
    }

    expect(useAlertStore.getState().alerts).toHaveLength(500);
    expect(useAlertStore.getState().alerts[0]?.id).toBe(799);
    expect(useAlertStore.getState().receivedCount).toBe(800);
  });

  it('preenche a lista com o snapshot da conexão', () => {
    // Sem snapshot o dashboard abre vazio, o que é indistinguível de estar quebrado.
    useAlertStore.getState().connect();
    const socket = FakeWebSocket.instances[0]!;
    socket.open();
    socket.emit('auth_ok', {});
    socket.emit('snapshot', [makeAlert({ id: 10 }), makeAlert({ id: 11 })]);

    expect(useAlertStore.getState().alerts).toHaveLength(2);
  });

  it('ignora mensagem malformada sem quebrar o feed', () => {
    useAlertStore.getState().connect();
    const socket = FakeWebSocket.instances[0]!;
    socket.open();
    socket.emit('auth_ok', {});

    socket.onmessage?.({ data: 'isto não é json' } as MessageEvent<string>);

    expect(useAlertStore.getState().connection).toBe('live');
  });

  it('entra em reconexão quando a conexão cai sozinha', () => {
    vi.useFakeTimers();
    useAlertStore.getState().connect();
    const socket = FakeWebSocket.instances[0]!;
    socket.open();
    socket.emit('auth_ok', {});

    socket.onclose?.({ code: 1006, reason: '' } as CloseEvent);
    expect(useAlertStore.getState().connection).toBe('reconnecting');

    // Não reconecta de imediato — esperar é o ponto. Dez abas reconectando na
    // mesma hora derrubariam a API que acabou de subir.
    vi.advanceTimersByTime(400);
    expect(FakeWebSocket.instances).toHaveLength(1);

    // Primeira retentativa em ~1s (1000ms de base + até 500ms de jitter).
    vi.advanceTimersByTime(1200);
    expect(FakeWebSocket.instances.length).toBeGreaterThan(1);

    useAlertStore.getState().disconnect();
    vi.useRealTimers();
  });

  it('não conecta sem chave configurada', () => {
    clearApiKey();
    useAlertStore.getState().connect();

    expect(useAlertStore.getState().connection).toBe('failed');
    expect(FakeWebSocket.instances).toHaveLength(0);
  });
});
