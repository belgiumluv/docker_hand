FROM ubuntu:24.04

# Базовые пакеты за один проход
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates bash supervisor inotify-tools openssl \
    liblua5.4-0 libpcre2-8-0 libssl3 libcap2 libsystemd0 zlib1g libzstd1 liblz4-1 \
    libgcrypt20 libgpg-error0 liblzma5 \
    python3 python3-requests python3-nacl sqlite3 \
    certbot python3-minimal \
 && mkdir -p /var/www/certbot /opt/ssl /var/log/supervisor \
 && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates bash curl supervisor inotify-tools openssl \
    liblua5.4-0 libpcre2-8-0 libssl3 libcap2 libsystemd0 zlib1g libzstd1 liblz4-1 \
    libgcrypt20 libgpg-error0 liblzma5 \
    python3 python3-requests python3-nacl sqlite3 \
    certbot python3-minimal \
 && mkdir -p /var/www/certbot /opt/ssl /var/log/supervisor \
 && rm -rf /var/lib/apt/lists/*




WORKDIR /app

ARG LEGO_VERSION=4.19.2
RUN apt-get update && apt-get install -y curl ca-certificates && \
    curl -L "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin lego && \
    chmod +x /usr/local/bin/lego && \
    rm -rf /var/lib/apt/lists/*



# HAProxy базовый конфиг/файлы
COPY haproxy-etc.tar.gz /tmp/haproxy-etc.tar.gz
RUN mkdir -p /etc/haproxy \
 && tar -xzf /tmp/haproxy-etc.tar.gz -C /etc/haproxy \
 && rm /tmp/haproxy-etc.tar.gz

# Текущий haproxy.cfg (если нужен поверх)
COPY configs/haproxy.cfg /etc/haproxy/haproxy.cfg

# Создаём нужные каталоги под БД, конфиги, vpn
RUN mkdir -p /var/lib/bd /app/configs /vpn /data /opt/ssl

# Все конфиги из локальной папки configs -> в /app/configs внутри образа
# (в т.ч. serverlist.json, masq_domain_list.json и др.)
COPY configs/ /app/configs/

# haproxy.cfg в стандартное место
COPY configs/haproxy.cfg /etc/haproxy/haproxy.cfg

# masq_domain_list.json нужен также по пути /vpn/masq_domain_list.json
# (как это было в docker-compose)
COPY configs/masq_domain_list.json /vpn/masq_domain_list.json

RUN mkdir -p /opt/ssl
COPY ssl/ /opt/ssl/
# (опционально) подготовим пустую БД, если скрипты ожидают существующий файл
# можно оставить только каталог, БД сама создастся при первом запуске
# RUN touch /var/lib/bd/bd.db


# Скрипт публикации домена ноды в Kubernetes
COPY docker/publish-node-domain.sh /usr/local/bin/publish-node-domain.sh
RUN chmod +x /usr/local/bin/publish-node-domain.sh


# --- "Золотая копия" для автосидирования /vpn при старте ---
RUN mkdir -p /opt/seed/vpn
COPY bin/sing-box /opt/seed/vpn/sing-box
COPY configs/server.json /opt/seed/vpn/server.json
RUN chmod +x /opt/seed/vpn/sing-box

# НЕ копируем прямо в /vpn — это будет сидироваться entrypoint'ом

# HAProxy бинарник (если используешь свой)
COPY bin/haproxy /usr/sbin/haproxy
RUN chmod +x /usr/sbin/haproxy

# Скрипты
COPY docker/sslwatch-haproxy.sh /usr/local/bin/sslwatch-haproxy.sh
RUN chmod +x /usr/local/bin/sslwatch-haproxy.sh

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/cfgwatch.sh /usr/local/bin/cfgwatch.sh
COPY docker/cfgwatch-haproxy.sh /usr/local/bin/cfgwatch-haproxy.sh
COPY docker/haproxy-reloader.sh /usr/local/bin/haproxy-reloader.sh
COPY docker/singbox-reloader.sh  /usr/local/bin/singbox-reloader.sh
RUN chmod +x /usr/local/bin/*.sh

# БД и init
COPY docker/sqlite-init.sh /usr/local/bin/sqlite-init.sh
RUN chmod +x /usr/local/bin/sqlite-init.sh

# Python-скрипты
COPY scripts /app/scripts
RUN chmod +x /app/scripts/*.py

# --- vpnserver ---
COPY bin/vpnserver /opt/vpnserver
COPY docker/run-vpnserver.sh /usr/local/bin/run-vpnserver.sh
RUN chmod +x /opt/vpnserver /usr/local/bin/run-vpnserver.sh

VOLUME ["/data", "/vpn", "/opt/ssl"]

EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
