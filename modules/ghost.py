#!/usr/bin/env python3
"""
SENTINELA — Módulo do modo furtivo (--mode ghost)
Criado por github.com/3rr0rrr

Fornece jitter aleatório entre requisições, rotação de User-Agent e rotação
de proxies a partir de uma lista (--proxy-list), para reduzir a
"impressão digital" de padrão fixo de requisições durante um engajamento
red-team furtivo. Só tem efeito quando config["ghost_mode"] é True — nos
demais modos, os módulos de scan continuam usando o rate_limit fixo normal.
"""

import random
import time


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


class GhostRotator:
    def __init__(self, config: dict):
        self.enabled     = bool(config.get("ghost_mode", False))
        self.jitter_min  = float(config.get("jitter_min", 0.8))
        self.jitter_max  = float(config.get("jitter_max", 4.5))
        self.proxies     = self._carregar_proxies(config.get("proxy_list_file"))
        self._proxy_idx  = 0

    def _carregar_proxies(self, path: str) -> list:
        if not path:
            return []
        try:
            with open(path) as f:
                return [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception:
            return []

    def proximo_user_agent(self) -> str:
        return random.choice(USER_AGENTS)

    def proximo_proxy(self):
        if not self.proxies:
            return None
        proxy = self.proxies[self._proxy_idx % len(self.proxies)]
        self._proxy_idx += 1
        return {"http": proxy, "https": proxy}

    def patch_session(self, session):
        """Rotaciona User-Agent (sempre) e proxy (se --proxy-list configurado)
        na sessão HTTP passada. Chamar antes de cada rajada de requisições
        para simular clientes diferentes a cada passo."""
        if not self.enabled or session is None:
            return
        session.headers["User-Agent"] = self.proximo_user_agent()
        proxy = self.proximo_proxy()
        if proxy:
            session.proxies.update(proxy)

    def jitter_sleep(self, fator: float = 1.0):
        """Dorme um tempo aleatório dentro da faixa de jitter configurada,
        em vez do rate_limit fixo — dificulta detecção por padrão de tempo."""
        if not self.enabled:
            return
        delay = random.uniform(self.jitter_min, self.jitter_max) * fator
        time.sleep(delay)
