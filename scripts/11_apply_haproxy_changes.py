#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import re
import os
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# --- Настройка базового префикса (на случай chroot/host-монтажа)
ROOT_PREFIX = Path(os.getenv("ROOT_PREFIX", "/")).resolve()

def under_root(p: str) -> str:
    """Склеивает путь относительно ROOT_PREFIX, гарантируя абсолютный путь."""
    return str((ROOT_PREFIX / p.lstrip("/")).resolve())

# Абсолютные пути по умолчанию
HAP_PATH     = under_root("/etc/haproxy/haproxy.cfg")
CHANGES_PATH = under_root("/vpn/changes_dict.json")
DOMAIN_PATH  = under_root("/vpn/msq_domain_list_vibork.json")

# Теги, для которых действительно есть path_beg в haproxy.cfg
TAG_TO_BACKENDS: Dict[str, List[str]] = {
    "v10-vless-ws": ["v10-vless-ws"],
    "v10-vless-grpc": ["v10-vless-grpc", "v10-vless-grpc-http"],
    "v10-vless-httpupgrade": ["v10-vless-httpupgrade"],
    "v10-vless-tcp": ["v10-vless-tcp", "v10-vless-tcp-http"],

    "v10-vmess-ws": ["v10-vmess-ws"],
    "v10-vmess-grpc": ["v10-vmess-grpc", "v10-vmess-grpc-http"],
    "v10-vmess-httpupgrade": ["v10-vmess-httpupgrade"],
    "v10-vmess-tcp": ["v10-vmess-tcp", "v10-vmess-tcp-http"],

    "v10-trojan-ws": ["v10-trojan-ws"],
    "v10-trojan-grpc": ["v10-trojan-grpc", "v10-trojan-grpc-http"],
    "v10-trojan-httpupgrade": ["v10-trojan-httpupgrade"],
    "v10-trojan-tcp": ["v10-trojan-tcp", "v10-trojan-tcp-http"],
}

def _ensure_leading_slash(p: str) -> str:
    p = (p or "").strip()
    return p if (not p or p.startswith("/")) else f"/{p}"

def _backend_line_regex(backend_name: str) -> re.Pattern:
    # Ищем: use_backend <backend_name> if { path_beg /OLD }
    return re.compile(rf'(use_backend\s+{re.escape(backend_name)}\s+if\s+\{{\s*path_beg\s+)(/[^ \}}\n]+)')

def _replace_paths(text: str, paths: Dict[str, str], notes: List[str]) -> str:
    for tag, new_val in (paths or {}).items():
        backends = TAG_TO_BACKENDS.get(tag)
        if not backends:
            notes.append(f"[WARN] Неизвестный тег '{tag}' — пропускаю.")
            continue

        new_path = _ensure_leading_slash(str(new_val))
        for be in backends:
            rx = _backend_line_regex(be)

            def _sub(m: re.Match) -> str:
                old = m.group(2)
                if old == new_path:
                    return m.group(1) + old
                notes.append(f"[PATH] {be}: {old} -> {new_path}")
                return m.group(1) + new_path

            text, n = rx.subn(_sub, text)
            if n == 0:
                notes.append(f"[MISS] use_backend {be} с path_beg не найден.")
    return text

def _replace_domains(text: str,
                     reality_domain: Optional[str],
                     shadow_domain: Optional[str],
                     notes: List[str]) -> str:
    """
    Меняет строго указанные места в конфиге:
      - Reality:
          use_backend sp_special_reality_tcp_http_43124 if { hdr(host) -i <...> }
          use_backend sp_special_reality_tcp_43124 if { req.ssl_sni -i <...> }
          server sp_special_reality_tcp_43124 <...>:80
      - ShadowTLS:
          use_backend shadowtls_decoy_http if { hdr(host) -i <...> }
          use_backend shadowtls if { req.ssl_sni -i <...> }
          server shadowtls_decoy_http <...>
          server shadowtls_decoy <...>
    """

    def sub(rx: re.Pattern, label: str, builder):
        nonlocal text
        def _do(m: re.Match) -> str:
            old_line = m.group(0)
            new_line = builder(m)
            if old_line.strip() != new_line.strip():
                notes.append(f"[{label}] {old_line.strip()}  ->  {new_line.strip()}")
            else:
                notes.append(f"[{label}] без изменений: {old_line.strip()}")
            return new_line
        text = rx.sub(_do, text)

    # === Reality ===
    if reality_domain:
        r = reality_domain.strip()

        # 1) hdr(host)
        rx1 = re.compile(
            r'(?P<prefix>use_backend\s+sp_special_reality_tcp_http_43124\s+if\s+\{\s*hdr\(host\)\s+-i\s+)(?P<host>\S+)(?P<suffix>\s*\})'
        )
        sub(rx1, "Reality hdr(host)",
            lambda m: f"{m.group('prefix')}{r}{m.group('suffix')}")

        # 2) req.ssl_sni
        rx2 = re.compile(
            r'(?P<prefix>use_backend\s+sp_special_reality_tcp_43124\s+if\s+\{\s*req\.ssl_sni\s+-i\s+)(?P<host>\S+)(?P<suffix>\s*\})'
        )
        sub(rx2, "Reality req.ssl_sni",
            lambda m: f"{m.group('prefix')}{r}{m.group('suffix')}")

        # 3) server ... :80
        rx3 = re.compile(
            r'(?P<prefix>\bserver\s+sp_special_reality_tcp_43124\s+)(?P<host>[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::80)(?P<suffix>\b.*)'
        )
        sub(rx3, "Reality server :80",
            lambda m: f"{m.group('prefix')}{r}:80{m.group('suffix')}")

    # === ShadowTLS ===
    if shadow_domain:
        s = shadow_domain.strip()

        # 4) hdr(host)
        rx4 = re.compile(
            r'(?P<prefix>use_backend\s+shadowtls_decoy_http\s+if\s+\{\s*hdr\(host\)\s+-i\s+)(?P<host>\S+)(?P<suffix>\s*\})'
        )
        sub(rx4, "ShadowTLS hdr(host)",
            lambda m: f"{m.group('prefix')}{s}{m.group('suffix')}")

        # 5) req.ssl_sni
        rx5 = re.compile(
            r'(?P<prefix>use_backend\s+shadowtls\s+if\s+\{\s*req\.ssl_sni\s+-i\s+)(?P<host>\S+)(?P<suffix>\s*\})'
        )
        sub(rx5, "ShadowTLS req.ssl_sni",
            lambda m: f"{m.group('prefix')}{s}{m.group('suffix')}")

        # 6) server shadowtls_decoy_http ...
        rx6 = re.compile(
            r'(?P<prefix>\bserver\s+shadowtls_decoy_http\s+)(?P<host>[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?P<suffix>\b.*)'
        )
        sub(rx6, "ShadowTLS server decoy_http",
            lambda m: f"{m.group('prefix')}{s}{m.group('suffix')}")

        # 7) server shadowtls_decoy ...
        rx7 = re.compile(
            r'(?P<prefix>\bserver\s+shadowtls_decoy\s+)(?P<host>[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?P<suffix>\b.*)'
        )
        sub(rx7, "ShadowTLS server decoy",
            lambda m: f"{m.group('prefix')}{s}{m.group('suffix')}")

    return text


def apply_haproxy_changes(
    haproxy_path: str,
    path_changes: Optional[Dict[str, str]] = None,
    reality_server_name: Optional[str] = None,
    shadowtls_server_name: Optional[str] = None,
    out_path: Optional[str] = None,
    dry_run: bool = False,
) -> Tuple[str, List[str]]:
    """
    Меняет конфиг haproxy:
      - paths: словарь {tag: "/new_path"} — меняем только указанные теги.
      - reality_server_name: опционально заменить домен для Reality.
      - shadowtls_server_name: опционально заменить домен для ShadowTLS.
    Ничего не указали — ничего не меняем.

    Возвращает (новый_текст, лог_изменений).
    """
    if not os.path.isfile(haproxy_path):
        raise FileNotFoundError(f"haproxy.cfg не найден: {haproxy_path}")

    with open(haproxy_path, "r", encoding="utf-8") as f:
        text = f.read()

    notes: List[str] = []

    # 1) пути по тегам
    if path_changes:
        text = _replace_paths(text, path_changes, notes)

    # 2) домены (только если заданы)
    if reality_server_name or shadowtls_server_name:
        text = _replace_domains(text, reality_server_name, shadowtls_server_name, notes)

    if dry_run:
        return text, notes

    # Запись с бэкапом
    write_path = out_path or haproxy_path
    if os.path.abspath(write_path) == os.path.abspath(haproxy_path):
        shutil.copy2(haproxy_path, haproxy_path + ".bak")
        notes.append(f"[BACKUP] Создан бэкап: {haproxy_path}.bak")

    with open(write_path, "w", encoding="utf-8") as f:
        f.write(text)
    notes.append(f"[WRITE] Записано: {write_path}")

    return text, notes

# --- Точка входа как скрипт ---
if __name__ == "__main__":
    # Проверяем входные файлы
    if not os.path.isfile(DOMAIN_PATH):
        raise FileNotFoundError(f"Список доменов (masq) не найден: {DOMAIN_PATH}")
    if not os.path.isfile(CHANGES_PATH):
        raise FileNotFoundError(f"Файл изменений путей не найден: {CHANGES_PATH}")
    if not os.path.isfile(HAP_PATH):
        raise FileNotFoundError(f"haproxy.cfg не найден: {HAP_PATH}")

    # DOMAIN_PATH ожидается как список из минимум 2 доменов
    with open(DOMAIN_PATH, 'r', encoding='utf-8') as f_dom:
        domain_list = json.load(f_dom)
        if not isinstance(domain_list, list) or len(domain_list) < 2:
            raise ValueError(f"{DOMAIN_PATH} должен быть списком длиной >= 2")
        reality_domain   = str(domain_list[0]).strip()
        shadowtls_domain = str(domain_list[1]).strip()

    with open(CHANGES_PATH, 'r', encoding='utf-8') as f_changes:
        path_changes = json.load(f_changes)
        if not isinstance(path_changes, dict):
            raise ValueError(f"{CHANGES_PATH} должен быть JSON-объектом с map тег->путь")

    _, log = apply_haproxy_changes(
        haproxy_path=HAP_PATH,
        path_changes=path_changes,
        reality_server_name=reality_domain or None,
        shadowtls_server_name=shadowtls_domain or None,
        out_path=HAP_PATH,
        dry_run=False
    )
    print("\n".join(log))
