import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

import { App } from './App';
import './styles/main.scss';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Alerta ao vivo chega pelo WebSocket; o REST serve o histórico, que muda
      // devagar. Revalidar a cada foco de janela só geraria carga à toa.
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        // 401 não melhora com retentativa — é chave errada.
        if (error instanceof Error && error.name === 'ApiError') {
          const status = (error as Error & { status?: number }).status;
          if (status === 401 || status === 403) return false;
        }
        return failureCount < 2;
      },
    },
  },
});

const container = document.getElementById('root');
if (!container) throw new Error('#root não encontrado');

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
