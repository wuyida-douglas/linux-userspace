#!/usr/bin/env bash
# Store PT proxy credentials locally without echoing the app password or
# putting it in argv, shell history, pipeline prompts or Docker image layers.
set -euo pipefail
if [ "$(id -u)" -eq 0 ]; then
    printf 'Run this as wuyida, not root.\n' >&2
    exit 1
fi
credential_dir="${HOME}/.config/pt-proxy"
credential_file="${credential_dir}/proxy-url"
if [ -t 0 ]; then
    read -r -p 'AD username [wuyida]: ' username
    username="${username:-wuyida}"
    read -r -s -p 'Authentik application password (not echoed): ' password
    printf '\n'
else
    printf 'Noninteractive: enter AD username on line 1 and application password on line 2.\n' >&2
    IFS= read -r username
    IFS= read -r password
fi
if [ -z "$username" ] || [ -z "$password" ]; then
    printf 'Both AD username and application password are required.\n' >&2
    exit 1
fi
umask 077
mkdir -p "$credential_dir"
encoded_user="$(USERNAME="$username" python3 -c 'import os, urllib.parse; print(urllib.parse.quote(os.environ["USERNAME"], safe=""))')"
encoded_password="$(PASSWORD="$password" python3 -c 'import os, urllib.parse; print(urllib.parse.quote(os.environ["PASSWORD"], safe=""))')"
printf 'http://%s:%s@proxy.pjlab.org.cn:23128\n' "$encoded_user" "$encoded_password" > "$credential_file"
unset password encoded_password encoded_user username
chmod 600 "$credential_file"

# shellcheck source=/dev/null
source "$(dirname "${BASH_SOURCE[0]}")/proxy-env.sh"
printf 'Testing authenticated proxy (credentials are not printed)...\n'
status="$(curl --silent --show-error --connect-timeout 8 --max-time 30 \
    --output /dev/null --write-out '%{http_code}' https://github.com/)"
printf 'GitHub via PT proxy: HTTP %s\n' "$status"
printf 'Credential file: %s (mode 600)\n' "$credential_file"
printf 'New login shells load ~/.profile; current Bash shell: source ~/.bashrc\n'
