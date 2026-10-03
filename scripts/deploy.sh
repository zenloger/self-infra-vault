#!/usr/bin/env bash
# Run in the checked-out server repository after copying a locally built dist/.
set -euo pipefail
cd "$(dirname "$0")/.."
test -s dist/index.html
test -s dist/app.js
test -s dist/vault-worker.js
sudo test -e /etc/letsencrypt/live/secret.zenlog.pro/fullchain.pem
if [ ! -x .venv/bin/python ]; then python3 -m venv .venv; fi
.venv/bin/python -m pip install --disable-pip-version-check --index-url https://pypi.org/simple -r requirements.lock.txt
if ! sudo test -e /etc/zenlog-vault.env; then
    sudo install -o root -g root -m 600 .env.example /etc/zenlog-vault.env
fi
sudo install -o root -g root -m 644 deploy/zenlog-vault.service /etc/systemd/system/zenlog-vault.service
sudo systemctl daemon-reload
sudo systemctl enable zenlog-vault
sudo systemctl restart zenlog-vault
curl --fail --silent --show-error --retry 5 --retry-connrefused --retry-delay 1 \
    -H 'Host: secret.zenlog.pro' http://127.0.0.1:8137/healthz
sudo install -o root -g root -m 644 deploy/secret.zenlog.pro.conf /etc/nginx/sites-available/secret.zenlog.pro
sudo ln -sfn /etc/nginx/sites-available/secret.zenlog.pro /etc/nginx/sites-enabled/secret.zenlog.pro
sudo nginx -t
sudo systemctl reload nginx
