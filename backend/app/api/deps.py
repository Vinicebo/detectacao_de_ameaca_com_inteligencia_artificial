"""Shared FastAPI dependencies: authentication and rate limiting."""

from __future__ import annotations

import hmac
import time
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from app.config import Settings, get_settings
from app.redis_client import get_redis

SettingsDep = Annotated[Settings, Depends(get_settings)]


async def require_api_key(
    settings: SettingsDep,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> str:
    """Valida o header X-API-Key.

    A comparação é em tempo constante: `==` em string vaza o tamanho do prefixo
    correto pelo tempo de resposta, o que permite descobrir a chave byte a byte.
    """
    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Header X-API-Key ausente",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    expected = settings.api_key.get_secret_value()
    if not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key inválida",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return x_api_key


ApiKeyDep = Annotated[str, Depends(require_api_key)]


async def rate_limit(request: Request, settings: SettingsDep, _: ApiKeyDep) -> None:
    """Janela fixa por minuto, por chave e por rota.

    Janela fixa deixa passar até 2x o limite na virada do minuto. Para proteger a
    própria API de um cliente descuidado isso basta — não é um controle de segurança.
    """
    limit = settings.rate_limit_per_minute
    if limit <= 0:
        return

    client = get_redis()
    window = int(time.time() // 60)
    route = request.scope.get("route")
    route_key = getattr(route, "path", request.url.path)
    key = f"ratelimit:{route_key}:{window}"

    try:
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, 120)
        current, _expire = await pipe.execute()
    except Exception:
        # Redis fora do ar não pode derrubar a API inteira. Falha aberto de propósito.
        return

    if int(current) > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Limite de {limit} requisições por minuto excedido",
            headers={"Retry-After": "60"},
        )


RateLimitDep = Depends(rate_limit)
