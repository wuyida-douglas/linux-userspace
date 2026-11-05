# Source this file in Bash. Credentials are stored separately, never in this file.
# Run /nvme/wuyida/新管线开发/config/setup-pt-proxy.sh once to create them.
if [ -n "${PT_PROXY_DISABLED:-}" ]; then
    return 0 2>/dev/null || exit 0
fi
_pt_proxy_credential="${PT_PROXY_CREDENTIAL_FILE:-$HOME/.config/pt-proxy/proxy-url}"
if [ -r "$_pt_proxy_credential" ]; then
    IFS= read -r _pt_proxy_url < "$_pt_proxy_credential"
    export HTTP_PROXY="$_pt_proxy_url" HTTPS_PROXY="$_pt_proxy_url"
    export http_proxy="$_pt_proxy_url" https_proxy="$_pt_proxy_url"
    export NO_PROXY="localhost,127.0.0.1,::1,.pjlab.org.cn,.sensetime.com,10.0.0.0/8,100.0.0.0/8,172.16.0.0/12,192.168.0.0/16,10.140.84.42,10.12.111.133"
    export no_proxy="$NO_PROXY"
    unset _pt_proxy_url
fi
unset _pt_proxy_credential
