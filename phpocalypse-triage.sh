#!/bin/sh
# phpocalypse-triage.sh - read-only triage collector for the PHP
# session.upload_progress vulnerabilities (CVE-2026-109618 / CVE-2026-109619).
#
# Gathers the web / PHP / system / security logs and session storage a responder
# needs to decide whether a host was hit, reviews the relevant session.* ini
# settings, flags and quarantines suspicious session files, and writes one zip
# bundle. It only reads: no setting is changed, nothing leaves the host.
#
# Run as root for full log coverage. POSIX sh, no external dependencies.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 JUMPSEC Ltd.

umask 077

PHPOC_VERSION="1.0"
LOG_CAP_BYTES=52428800        # 50 MB per-log cap; matched lines are kept in full
SNIPPET_MAX=160

OUT_DIR=""
QUIET=0

usage() {
    cat <<EOF
phpocalypse-triage $PHPOC_VERSION - PHP session.upload_progress triage collector

Usage: sh phpocalypse-triage.sh [options]

  -o DIR   write the output zip to DIR (default: current directory)
  -q       quieter console output
  -h       show this help

Writes phpocalypse-<hostname>-<timestamp>.zip. Run with sudo for full coverage.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -o) OUT_DIR="$2"; shift 2 ;;
        -q) QUIET=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "phpocalypse: unknown option: $1" >&2; exit 2 ;;
    esac
done

say()  { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }
step() { [ "$QUIET" -eq 1 ] || printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

RAW_HOST="$( (hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || uname -n) 2>/dev/null )"
[ -n "$RAW_HOST" ] || RAW_HOST="unknown-host"
HOST="$(printf '%s' "$RAW_HOST" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-64)"
TS="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || date +%Y%m%d-%H%M%S)"
BUNDLE="phpocalypse-${HOST}-${TS}"

UID_NUM="$(id -u 2>/dev/null || echo 1000)"
IS_ROOT=0
[ "$UID_NUM" = "0" ] && IS_ROOT=1

# decide where the final zip lands
if [ -z "$OUT_DIR" ]; then
    if   [ -w "$PWD" ];  then OUT_DIR="$PWD"
    elif [ -w "$HOME" ]; then OUT_DIR="$HOME"
    else OUT_DIR="/tmp"; fi
fi
if [ ! -d "$OUT_DIR" ] || [ ! -w "$OUT_DIR" ]; then
    warn "output directory not writable: $OUT_DIR"; exit 1
fi

# stage under a temp dir so we never collect our own output
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/phpoc.XXXXXX" 2>/dev/null)"
if [ -z "$STAGE" ] || [ ! -d "$STAGE" ]; then
    warn "could not create temporary working directory"; exit 1
fi
ROOT="$STAGE/$BUNDLE"
mkdir -p "$ROOT/web" "$ROOT/php" "$ROOT/system" "$ROOT/security" \
         "$ROOT/findings" "$ROOT/findings/artifacts" "$ROOT/findings/log-hits"

cleanup() { rm -rf "$STAGE" 2>/dev/null; }
trap cleanup EXIT INT TERM

COLLECTLOG="$ROOT/findings/collection.log"
: > "$COLLECTLOG"
logc() { printf '%s\n' "$*" >> "$COLLECTLOG"; }
logc "phpocalypse-triage $PHPOC_VERSION"
logc "started: $(date -u 2>/dev/null)"
logc "host: $RAW_HOST"
logc "euid: $UID_NUM (root=$IS_ROOT)"

# pipe-delimited scratch files, turned into JSON at the end
MANIFEST_TMP="$STAGE/manifest.list"   # dest_rel|status|sha256|bytes|mtime|source
HITS_TMP="$STAGE/hits.list"           # chain|indicator|path|sha256|mtime|snippet
RECS_TMP="$STAGE/recs.list"           # one recommendation per line
: > "$MANIFEST_TMP"; : > "$HITS_TMP"; : > "$RECS_TMP"

have() { command -v "$1" >/dev/null 2>&1; }

# pick whatever sha256 tool exists
SHA_TOOL=""
if   have sha256sum; then SHA_TOOL="sha256sum"
elif have shasum;    then SHA_TOOL="shasum -a 256"
elif have openssl;   then SHA_TOOL="openssl"
fi

sha256_of() {
    [ -f "$1" ] || { echo ""; return; }
    case "$SHA_TOOL" in
        sha256sum)       sha256sum "$1" 2>/dev/null | awk '{print $1}' ;;
        "shasum -a 256") shasum -a 256 "$1" 2>/dev/null | awk '{print $1}' ;;
        openssl)         openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}' ;;
        *)               echo "" ;;
    esac
}

file_mtime() {
    [ -e "$1" ] || { echo ""; return; }
    date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
      || stat -c '%y' "$1" 2>/dev/null \
      || stat -f '%Sm' "$1" 2>/dev/null \
      || echo ""
}

file_size() {
    [ -e "$1" ] || { echo 0; return; }
    wc -c < "$1" 2>/dev/null | tr -d ' ' || echo 0
}

# escape a string for embedding in JSON (no surrounding quotes)
jstr() {
    printf '%s' "$1" \
      | tr -d '\000\r' \
      | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
      | awk 'BEGIN{ORS=""}{gsub(/\t/,"\\t"); if(NR>1) printf "\\n"; printf "%s",$0}'
}

add_rec() { printf '%s\n' "$1" >> "$RECS_TMP"; }

# record a file already present in the bundle (hashes it; does not copy)
manifest_add() {
    _d="$1"; _s="$2"; _src="$3"; _abs="$ROOT/$_d"
    _h=""; _b=0; _m=""
    if [ -f "$_abs" ]; then _h="$(sha256_of "$_abs")"; _b="$(file_size "$_abs")"; _m="$(file_mtime "$_abs")"; fi
    printf '%s|%s|%s|%s|%s|%s\n' "$_d" "$_s" "$_h" "$_b" "$_m" "$_src" >> "$MANIFEST_TMP"
}

# copy src into the bundle (tail-capping oversized logs) and record the result
collect_file() {
    _src="$1"; _dest="$2"; _abs="$ROOT/$_dest"
    if [ ! -e "$_src" ]; then manifest_add "$_dest" "absent" "$_src"; return 1; fi
    if [ ! -r "$_src" ]; then
        manifest_add "$_dest" "unreadable(perm)" "$_src"
        logc "unreadable: $_src"
        return 1
    fi
    mkdir -p "$(dirname "$_abs")" 2>/dev/null
    _sz="$(file_size "$_src")"
    if [ "$_sz" -gt "$LOG_CAP_BYTES" ] 2>/dev/null; then
        tail -c "$LOG_CAP_BYTES" "$_src" > "${_abs}.tailcapped" 2>/dev/null
        manifest_add "${_dest}.tailcapped" "collected(tail-capped from ${_sz} bytes)" "$_src"
        logc "tail-capped ($_sz bytes): $_src"
    else
        if cp -p "$_src" "$_abs" 2>/dev/null; then
            manifest_add "$_dest" "collected" "$_src"
        else
            manifest_add "$_dest" "copy-failed" "$_src"
            logc "copy-failed: $_src"
            return 1
        fi
    fi
    return 0
}

# collect_glob DEST_SUBDIR GLOB...
collect_glob() {
    _sub="$1"; shift
    for _p in "$@"; do
        for _f in $_p; do
            [ -e "$_f" ] || continue
            [ -f "$_f" ] || continue
            _base="$(printf '%s' "$_f" | sed 's#^/##; s#/#__#g')"
            collect_file "$_f" "$_sub/$_base"
        done
    done
}

# platform / environment
step "Detecting platform"
OS_ID=""; OS_NAME=""; OS_LIKE=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release 2>/dev/null
    OS_ID="$ID"; OS_NAME="$PRETTY_NAME"; OS_LIKE="$ID_LIKE"
fi
[ -n "$OS_NAME" ] || OS_NAME="$(uname -sr 2>/dev/null)"
KERNEL="$(uname -r 2>/dev/null)"

IN_CONTAINER=0; CONTAINER_KIND=""
if [ -f /.dockerenv ]; then IN_CONTAINER=1; CONTAINER_KIND="docker"; fi
if [ -f /run/.containerenv ]; then IN_CONTAINER=1; CONTAINER_KIND="${CONTAINER_KIND:-podman}"; fi
if [ -r /proc/1/cgroup ] && grep -qaE 'docker|kubepods|lxc|containerd' /proc/1/cgroup 2>/dev/null; then
    IN_CONTAINER=1; CONTAINER_KIND="${CONTAINER_KIND:-container}"
fi
logc "os: $OS_NAME (id=$OS_ID like=$OS_LIKE)"
logc "kernel: $KERNEL"
logc "container: $IN_CONTAINER ($CONTAINER_KIND)"

if [ "$IS_ROOT" -ne 1 ]; then
    warn "Not running as root -- some logs and session files may be unreadable."
    warn "For complete collection, re-run with:  sudo sh $0"
    logc "WARNING: not root; coverage may be incomplete"
fi

# PHP binaries + passive config review
step "Discovering PHP and checking configuration (passive)"
PHP_SUMMARY="$ROOT/php/php-config-summary.txt"
: > "$PHP_SUMMARY"
{
    echo "phpocalypse PHP configuration summary"
    echo "host: $RAW_HOST"
    echo "generated: $(date -u 2>/dev/null)"
    echo "note: CLI 'php -i' reflects CLI settings; FPM/web pools may differ."
    echo "      FPM/web ini files are copied under php/ for direct review."
    echo "================================================================="
    echo
} >> "$PHP_SUMMARY"

PHP_BINS=""
for c in php php8 php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 php7.4 php7.3 php7.2 \
         /usr/bin/php /usr/local/bin/php /opt/php/bin/php /usr/sbin/php-fpm; do
    p="$(command -v "$c" 2>/dev/null)"
    [ -n "$p" ] || { [ -x "$c" ] && p="$c"; }
    [ -n "$p" ] || continue
    case " $PHP_BINS " in *" $p "*) ;; *) PHP_BINS="$PHP_BINS $p" ;; esac
done
for c in php-fpm php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php-fpm8.1 php-fpm8.0; do
    p="$(command -v "$c" 2>/dev/null)" || continue
    [ -n "$p" ] || continue
    case " $PHP_BINS " in *" $p "*) ;; *) PHP_BINS="$PHP_BINS $p" ;; esac
done

SESSION_SAVE_PATHS=""
add_savepath() {
    _sp="$(printf '%s' "$1" | sed 's/.*;//')"   # strip the optional "N;" depth prefix
    [ -n "$_sp" ] || return
    case " $SESSION_SAVE_PATHS " in *" $_sp "*) ;; *) SESSION_SAVE_PATHS="$SESSION_SAVE_PATHS $_sp" ;; esac
}

if [ -z "$PHP_BINS" ]; then
    echo "NO PHP BINARY FOUND ON PATH OR COMMON LOCATIONS." >> "$PHP_SUMMARY"
    echo "(PHP may still run via a web-server module - checking ini files directly.)" >> "$PHP_SUMMARY"
    logc "php: no binary discovered"
fi

CONF_RISK=0
for php in $PHP_BINS; do
    ver="$("$php" -v 2>/dev/null | head -n1)"
    tag="$(printf '%s' "$php" | sed 's#/#_#g; s/^_//')"
    {
        echo "----- $php"
        echo "version: ${ver:-unknown}"
    } >> "$PHP_SUMMARY"
    "$php" -i > "$ROOT/php/phpinfo-${tag}.txt" 2>/dev/null
    manifest_add "php/phpinfo-${tag}.txt" "collected" "$php -i"

    # read the directives straight out of the -i dump; nothing is executed
    ii="$ROOT/php/phpinfo-${tag}.txt"
    getd() { grep -E "^$1 " "$ii" 2>/dev/null | head -n1 | awk -F'=>' '{print $2}' | sed 's/^ *//; s/ *$//'; }
    up="$(getd 'session.upload_progress.enabled')"
    uc="$(getd 'session.use_only_cookies')"
    sm="$(getd 'session.use_strict_mode')"
    sh_="$(getd 'session.serialize_handler')"
    sp="$(getd 'session.save_path')"
    cl="$(getd 'session.upload_progress.cleanup')"
    {
        echo "  session.upload_progress.enabled : ${up:-?}"
        echo "  session.use_only_cookies        : ${uc:-?}"
        echo "  session.use_strict_mode         : ${sm:-?}"
        echo "  session.serialize_handler       : ${sh_:-?}"
        echo "  session.upload_progress.cleanup : ${cl:-?}"
        echo "  session.save_path               : ${sp:-?}"
        echo
    } >> "$PHP_SUMMARY"
    [ -n "$sp" ] && add_savepath "$sp"

    case "$up" in
        On|on|1|On*) CONF_RISK=1
            add_rec "[$php] session.upload_progress.enabled is ON -- set it to Off in php.ini. This is the primary vector for all validated chains (CVE-2026-109618/109619)." ;;
    esac
    case "$uc" in
        Off|off|0|Off*|"") CONF_RISK=1
            add_rec "[$php] session.use_only_cookies is not On -- set session.use_only_cookies = On to stop attacker-controlled session IDs via the request body." ;;
    esac
    case "$sm" in
        Off|off|0|Off*|"") CONF_RISK=1
            add_rec "[$php] session.use_strict_mode is not On -- set session.use_strict_mode = On to prevent session fixation." ;;
    esac
done

# the FPM/web ini and pool files are authoritative for the web context
step "Collecting PHP ini and FPM pool files"
collect_glob "php/ini" \
    "/etc/php/*/fpm/php.ini" "/etc/php/*/apache2/php.ini" "/etc/php/*/cli/php.ini" \
    "/etc/php.ini" "/etc/php*/php.ini" "/usr/local/etc/php/php.ini" \
    "/etc/php/*/fpm/pool.d/*.conf" "/etc/php-fpm.d/*.conf" "/etc/php-fpm.conf" \
    "/usr/local/etc/php-fpm.d/*.conf"

# a split serialize_handler across directories is the Chain C precondition
step "Checking for mixed session.serialize_handler (Chain C precondition)"
SH_VALUES=""
scan_sh() {
    for f in "$@"; do
        [ -f "$f" ] && [ -r "$f" ] || continue
        v="$(grep -aiE 'serialize_handler' "$f" 2>/dev/null | grep -aiv '^\s*;' | head -n1)"
        [ -n "$v" ] && SH_VALUES="$SH_VALUES
$f: $v"
    done
}
WEBROOTS="/var/www /srv/www /srv/http /usr/share/nginx /var/www/html"
OVR_FILES=""
for wr in $WEBROOTS; do
    [ -d "$wr" ] || continue
    OVR_FILES="$OVR_FILES $(find "$wr" -maxdepth 6 \( -name '.user.ini' -o -name '.htaccess' \) -type f 2>/dev/null | head -n 200)"
done
scan_sh $OVR_FILES /etc/php/*/fpm/php.ini /etc/php.ini
if [ -n "$SH_VALUES" ]; then
    printf 'serialize_handler references found:\n%s\n' "$SH_VALUES" > "$ROOT/php/serialize_handler-refs.txt"
    manifest_add "php/serialize_handler-refs.txt" "collected" "web-root scan"
    distinct="$(printf '%s' "$SH_VALUES" | grep -aoiE 'serialize_handler[^;]*' | grep -aoiE '(php_serialize|php_binary|php|wddx)' | sort -u | tr '\n' ' ')"
    nd="$(printf '%s' "$distinct" | wc -w | tr -d ' ')"
    if [ "$nd" -gt 1 ]; then
        add_rec "Mixed session.serialize_handler values detected across directories ($distinct). With a shared session.save_path this enables Chain C object injection -- make the handler consistent everywhere."
    fi
fi

manifest_add "php/php-config-summary.txt" "collected" "generated"

# scan session storage for injected code / objects, quarantine any hits
step "Scanning session storage for indicators of compromise"
for d in /var/lib/php/sessions /var/lib/php-sessions /var/lib/php/session \
         /var/lib/php /tmp /var/tmp; do
    case " $SESSION_SAVE_PATHS " in *" $d "*) ;; *) SESSION_SAVE_PATHS="$SESSION_SAVE_PATHS $d" ;; esac
done
logc "session dirs scanned:$SESSION_SAVE_PATHS"

SESS_SCANNED=0
SESS_HIT=0
for dir in $SESSION_SAVE_PATHS; do
    [ -d "$dir" ] || continue
    if [ ! -r "$dir" ]; then logc "session dir unreadable: $dir"; continue; fi
    if [ "$dir" = "/tmp" ] || [ "$dir" = "/var/tmp" ]; then
        logc "note: web server may use PrivateTmp; $dir sessions may be isolated from this view"
    fi
    for f in "$dir"/sess_*; do
        [ -e "$f" ] || continue
        [ -f "$f" ] || continue
        [ -r "$f" ] || { logc "session unreadable: $f"; continue; }
        SESS_SCANNED=$((SESS_SCANNED+1))
        chain=""; indicator=""; snippet=""
        # Chain A: raw PHP tags written into a session file
        if grep -aqF '<?php' "$f" 2>/dev/null || grep -aqF '<?=' "$f" 2>/dev/null; then
            chain="A"; indicator="php-tag-in-session"
            snippet="$(grep -am1 -oaE '.{0,20}<\?(php|=).{0,120}' "$f" 2>/dev/null | head -n1)"
        fi
        # Chain C: serialized object smuggled in after a pipe
        if grep -aqF '|O:' "$f" 2>/dev/null; then
            if [ -n "$chain" ]; then chain="A+C"; else chain="C"; fi
            indicator="${indicator:+$indicator,}pipe-object-injection"
            s2="$(grep -am1 -oaE '.{0,20}\|O:[0-9]+:"[^"]*".{0,80}' "$f" 2>/dev/null | head -n1)"
            [ -n "$s2" ] && snippet="${snippet:+$snippet | }$s2"
        fi
        if [ -n "$chain" ]; then
            SESS_HIT=$((SESS_HIT+1))
            qbase="$(basename "$f")"
            dkey="$(printf '%s' "${dir#/}" | sed 's#/#__#g')"
            mkdir -p "$ROOT/findings/artifacts/sessions" 2>/dev/null
            qdest="findings/artifacts/sessions/${dkey}__${qbase}"
            cp -p "$f" "$ROOT/$qdest" 2>/dev/null   # copy only; original untouched
            qh="$(sha256_of "$ROOT/$qdest")"; qm="$(file_mtime "$f")"
            manifest_add "$qdest" "quarantined" "$f"
            snippet="$(printf '%s' "$snippet" | cut -c1-$SNIPPET_MAX)"
            printf '%s|%s|%s|%s|%s|%s\n' "$chain" "$indicator" "$f" "$qh" "$qm" "$snippet" >> "$HITS_TMP"
            warn "IOC: session file $f (chain $chain)"
        fi
    done
done
logc "session files scanned: $SESS_SCANNED; hits: $SESS_HIT"

# Priority-1 log collection
step "Collecting web server logs"
collect_glob "web" \
    "/var/log/apache2/access.log*" "/var/log/apache2/error.log*" \
    "/var/log/apache2/other_vhosts_access.log*" \
    "/var/log/httpd/access_log*" "/var/log/httpd/error_log*" \
    "/var/log/httpd/*access*" "/var/log/httpd/*error*" \
    "/var/log/nginx/access.log*" "/var/log/nginx/error.log*" \
    "/var/log/nginx/*.log"

step "Collecting PHP and PHP-FPM logs"
collect_glob "php" \
    "/var/log/php*.log" "/var/log/php/*.log" \
    "/var/log/php*-fpm.log" "/var/log/php-fpm/*.log" "/var/log/php-fpm.log" \
    "/var/log/php*fpm*/*.log"

step "Collecting application logs (Laravel / WordPress / generic)"
APP_COUNT=0
for wr in $WEBROOTS; do
    [ -d "$wr" ] || continue
    for f in $(find "$wr" -maxdepth 6 \
                 \( -path '*/storage/logs/*.log' -o -name 'debug.log' -o -name 'laravel.log' \) \
                 -type f 2>/dev/null | head -n 100); do
        [ -f "$f" ] && [ -r "$f" ] || continue
        base="$(printf '%s' "$f" | sed 's#^/##; s#/#__#g')"
        collect_file "$f" "php/app/$base" && APP_COUNT=$((APP_COUNT+1))
    done
done
logc "application logs collected: $APP_COUNT"

step "Collecting system logs"
collect_glob "system" \
    "/var/log/syslog*" "/var/log/messages*" "/var/log/kern.log*" \
    "/var/log/auth.log*" "/var/log/secure*" \
    "/var/log/audit/audit.log*" "/var/log/cron*"

if have journalctl; then
    step "Collecting journald entries"
    for unit in apache2 httpd nginx php-fpm php8.3-fpm php8.4-fpm php8.5-fpm php8.2-fpm; do
        if journalctl -u "$unit" --no-pager -n 100000 >/dev/null 2>&1; then
            journalctl -u "$unit" --no-pager -n 100000 > "$ROOT/system/journal-${unit}.txt" 2>/dev/null
            [ -s "$ROOT/system/journal-${unit}.txt" ] \
              && manifest_add "system/journal-${unit}.txt" "collected" "journalctl -u $unit" \
              || rm -f "$ROOT/system/journal-${unit}.txt"
        fi
    done
    journalctl -k --no-pager -n 50000 > "$ROOT/system/journal-kernel.txt" 2>/dev/null
    [ -s "$ROOT/system/journal-kernel.txt" ] \
      && manifest_add "system/journal-kernel.txt" "collected" "journalctl -k" \
      || rm -f "$ROOT/system/journal-kernel.txt"
fi

# security telemetry where it happens to exist (best effort)
step "Collecting available security telemetry"
collect_glob "security" \
    "/var/log/modsec_audit.log*" "/var/log/modsecurity/*.log" \
    "/var/log/fail2ban.log*" "/var/log/ufw.log*" \
    "/var/log/suricata/*.log" "/var/log/suricata/eve.json*"

# read-only state snapshots
snap() {
    _dest="$1"; shift
    if have "$1"; then
        "$@" > "$ROOT/security/$_dest" 2>/dev/null
        [ -s "$ROOT/security/$_dest" ] \
          && manifest_add "security/$_dest" "collected" "$*" \
          || rm -f "$ROOT/security/$_dest"
    fi
}
[ "$IS_ROOT" -eq 1 ] && snap "iptables.txt"  iptables-save
[ "$IS_ROOT" -eq 1 ] && snap "nftables.txt"  nft list ruleset
snap "ufw-status.txt" ufw status verbose
if have getenforce; then getenforce > "$ROOT/security/selinux-mode.txt" 2>/dev/null; manifest_add "security/selinux-mode.txt" "collected" "getenforce"; fi
if have ausearch; then
    ausearch -m avc -ts recent > "$ROOT/security/selinux-avc-recent.txt" 2>/dev/null
    [ -s "$ROOT/security/selinux-avc-recent.txt" ] \
      && manifest_add "security/selinux-avc-recent.txt" "collected" "ausearch -m avc -ts recent" \
      || rm -f "$ROOT/security/selinux-avc-recent.txt"
fi

if [ "$IN_CONTAINER" -eq 1 ]; then
    cat > "$ROOT/system/CONTAINER-NOTICE.txt" <<EOF
This host appears to be a $CONTAINER_KIND container.
Web/PHP logs may be written to the container's stdout/stderr and captured by
the container runtime on the HOST, not inside this filesystem.

To collect those, run on the container host (not inside the container):
    docker logs <container-name>  >  <container-name>.stdout.log  2>&1

Include that file with this bundle when you send it for review.
EOF
    manifest_add "system/CONTAINER-NOTICE.txt" "collected" "generated"
fi

# pull the known exploitation signatures out of whatever logs we collected
step "Extracting known exploitation signatures from logs"
LOG_SIG_HITS=0
ERRSIG='Failed to decode session object|Failed to read session data'
scan_logs() {
    for src in "$ROOT/web"/* "$ROOT/php"/* "$ROOT/php/app"/* "$ROOT/system"/*; do
        [ -f "$src" ] || continue
        base="$(basename "$src")"
        out="$ROOT/findings/log-hits/${base}.hits.txt"
        : > "$out.tmp"
        # Chain C handler-mismatch error-log line
        grep -aE "$ERRSIG" "$src" 2>/dev/null >> "$out.tmp"
        # upload_progress abuse wherever request bodies get logged (WAF/modsec/debug)
        grep -aE 'PHP_SESSION_UPLOAD_PROGRESS' "$src" 2>/dev/null >> "$out.tmp"
        # Chain A LFI: a request that names a session file
        grep -aiE 'sess_[a-z0-9]{10,}' "$src" 2>/dev/null \
          | grep -aiE 'GET|POST|\?|/' >> "$out.tmp"
        # injected PHP tags showing up in a logged request
        grep -aF '<?php' "$src" 2>/dev/null >> "$out.tmp"
        if [ -s "$out.tmp" ]; then
            sort -u "$out.tmp" > "$out"; rm -f "$out.tmp"
            n="$(wc -l < "$out" | tr -d ' ')"
            LOG_SIG_HITS=$((LOG_SIG_HITS + n))
            manifest_add "findings/log-hits/${base}.hits.txt" "collected" "$src"
            firstline="$(head -n1 "$out" | cut -c1-$SNIPPET_MAX)"
            printf 'LOG|log-signature|%s|%s|%s|%s\n' "$src" "" "" "$firstline" >> "$HITS_TMP"
            warn "IOC: $n log signature line(s) in $base"
        else
            rm -f "$out.tmp"
        fi
    done
}
scan_logs
logc "log signature lines: $LOG_SIG_HITS"

# verdict + reports
step "Writing findings and manifest"

TOTAL_IOC=$((SESS_HIT + LOG_SIG_HITS))
COVERAGE_GAP=0
if [ "$IS_ROOT" -ne 1 ]; then COVERAGE_GAP=1; fi
grep -q 'unreadable' "$MANIFEST_TMP" && COVERAGE_GAP=1

if [ "$TOTAL_IOC" -gt 0 ]; then
    VERDICT="INDICATORS FOUND"
    VERDICT_NOTE="Known exploitation indicators were observed. Treat as suspected compromise pending review; preserve this host and do not wipe logs."
elif [ "$COVERAGE_GAP" -eq 1 ]; then
    VERDICT="INCOMPLETE - ELEVATED COLLECTION NEEDED"
    VERDICT_NOTE="No indicators were found in the data that could be read, but collection was incomplete (see manifest.json coverage). Re-run as root, or additional sources may be requested."
else
    VERDICT="NO INDICATORS"
    VERDICT_NOTE="No known indicators were found in the collected data. This is not a guarantee of safety; assess alongside wider telemetry."
fi

FT="$ROOT/findings/findings.txt"
{
    echo "==============================================================="
    echo " VERDICT: $VERDICT"
    echo "==============================================================="
    echo
    echo "$VERDICT_NOTE"
    echo
    echo "phpocalypse-triage $PHPOC_VERSION"
    echo "host        : $RAW_HOST"
    echo "os          : $OS_NAME"
    echo "kernel      : $KERNEL"
    echo "container   : $([ "$IN_CONTAINER" -eq 1 ] && echo "yes ($CONTAINER_KIND)" || echo no)"
    echo "collected   : $(date -u 2>/dev/null)"
    echo "run as root : $([ "$IS_ROOT" -eq 1 ] && echo yes || echo 'NO (coverage limited)')"
    echo
    echo "--- IOC SUMMARY ---"
    echo "session files scanned        : $SESS_SCANNED"
    echo "suspicious session files     : $SESS_HIT"
    echo "log signature lines matched  : $LOG_SIG_HITS"
    echo
    if [ "$SESS_HIT" -gt 0 ] || [ "$LOG_SIG_HITS" -gt 0 ]; then
        echo "--- INDICATORS (detail) ---"
        while IFS='|' read -r chain ind path hash mtime snip; do
            [ -n "$chain" ] || continue
            if [ "$chain" = "LOG" ]; then
                echo "  [LOG]  $path"
                echo "         first match: $snip"
            else
                echo "  [CHAIN $chain]  $path"
                echo "         indicator  : $ind"
                echo "         sha256     : $hash"
                echo "         mtime      : $mtime"
                echo "         snippet    : $snip"
            fi
        done < "$HITS_TMP"
        echo
    fi
    echo "--- CONFIGURATION RECOMMENDATIONS ---"
    if [ -s "$RECS_TMP" ]; then
        i=1
        while IFS= read -r r; do
            [ -n "$r" ] || continue
            echo "  $i. $r"
            i=$((i+1))
        done < "$RECS_TMP"
    else
        echo "  None -- observed PHP settings already match the hardened baseline"
        echo "  (upload_progress off, use_only_cookies on, use_strict_mode on)."
    fi
    echo
    echo "--- NEXT STEPS ---"
    echo "  Provide ${BUNDLE}.zip to your incident-response contact."
    echo "  JUMPSEC clients: upload it via the JSEC portal."
    echo "  Do not delete logs or session files until the review is complete."
    echo "  See manifest.json for the full inventory and coverage report."
} > "$FT"
manifest_add "findings/findings.txt" "collected" "generated"

FJ="$ROOT/findings/findings.json"
{
    printf '{\n'
    printf '  "tool": "phpocalypse-triage",\n'
    printf '  "version": "%s",\n' "$PHPOC_VERSION"
    printf '  "event": "CVE-2026-109618/CVE-2026-109619 session.upload_progress",\n'
    printf '  "host": "%s",\n' "$(jstr "$RAW_HOST")"
    printf '  "os": "%s",\n' "$(jstr "$OS_NAME")"
    printf '  "kernel": "%s",\n' "$(jstr "$KERNEL")"
    printf '  "container": %s,\n' "$([ "$IN_CONTAINER" -eq 1 ] && echo true || echo false)"
    printf '  "collected_utc": "%s",\n' "$(jstr "$(date -u 2>/dev/null)")"
    printf '  "ran_as_root": %s,\n' "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)"
    printf '  "verdict": "%s",\n' "$(jstr "$VERDICT")"
    printf '  "coverage_gap": %s,\n' "$([ "$COVERAGE_GAP" -eq 1 ] && echo true || echo false)"
    printf '  "counts": { "session_scanned": %s, "session_hits": %s, "log_signature_lines": %s },\n' \
        "$SESS_SCANNED" "$SESS_HIT" "$LOG_SIG_HITS"
    printf '  "indicators": [\n'
    first=1
    while IFS='|' read -r chain ind path hash mtime snip; do
        [ -n "$chain" ] || continue
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    { "type": "%s", "chain": "%s", "indicator": "%s", "path": "%s", "sha256": "%s", "mtime": "%s", "snippet": "%s" }' \
            "$([ "$chain" = "LOG" ] && echo "log" || echo "session")" \
            "$(jstr "$chain")" "$(jstr "$ind")" "$(jstr "$path")" "$(jstr "$hash")" "$(jstr "$mtime")" "$(jstr "$snip")"
    done < "$HITS_TMP"
    printf '\n  ],\n'
    printf '  "recommendations": [\n'
    first=1
    while IFS= read -r r; do
        [ -n "$r" ] || continue
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    "%s"' "$(jstr "$r")"
    done < "$RECS_TMP"
    printf '\n  ]\n'
    printf '}\n'
} > "$FJ"
manifest_add "findings/findings.json" "collected" "generated"

MF="$ROOT/manifest.json"
{
    printf '{\n'
    printf '  "tool": "phpocalypse-triage",\n'
    printf '  "version": "%s",\n' "$PHPOC_VERSION"
    printf '  "bundle": "%s",\n' "$(jstr "$BUNDLE")"
    printf '  "host": "%s",\n' "$(jstr "$RAW_HOST")"
    printf '  "hostname_sanitised": "%s",\n' "$(jstr "$HOST")"
    printf '  "os": "%s",\n' "$(jstr "$OS_NAME")"
    printf '  "os_id": "%s",\n' "$(jstr "$OS_ID")"
    printf '  "kernel": "%s",\n' "$(jstr "$KERNEL")"
    printf '  "container": %s,\n' "$([ "$IN_CONTAINER" -eq 1 ] && echo true || echo false)"
    printf '  "container_kind": "%s",\n' "$(jstr "$CONTAINER_KIND")"
    printf '  "collected_utc": "%s",\n' "$(jstr "$(date -u 2>/dev/null)")"
    printf '  "ran_as_root": %s,\n' "$([ "$IS_ROOT" -eq 1 ] && echo true || echo false)"
    printf '  "session_dirs_scanned": "%s",\n' "$(jstr "$SESSION_SAVE_PATHS")"
    printf '  "verdict": "%s",\n' "$(jstr "$VERDICT")"
    printf '  "files": [\n'
    first=1
    while IFS='|' read -r drel status hash bytes mtime source; do
        [ -n "$drel" ] || continue
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    { "path": "%s", "status": "%s", "sha256": "%s", "bytes": "%s", "mtime": "%s", "source": "%s" }' \
            "$(jstr "$drel")" "$(jstr "$status")" "$(jstr "$hash")" "$(jstr "$bytes")" "$(jstr "$mtime")" "$(jstr "$source")"
    done < "$MANIFEST_TMP"
    printf '\n  ]\n'
    printf '}\n'
} > "$MF"

logc "finished: $(date -u 2>/dev/null)"
logc "verdict: $VERDICT"

# package everything into one zip (fall back through python/jar, then tar.gz)
step "Packaging bundle"
ZIP_PATH="$OUT_DIR/${BUNDLE}.zip"
PACKAGED=""

if have zip; then
    ( cd "$STAGE" && zip -r -q -X "$ZIP_PATH" "$BUNDLE" ) && PACKAGED="zip"
fi
if [ -z "$PACKAGED" ] && have python3; then
    ( cd "$STAGE" && python3 -c "import shutil,sys; shutil.make_archive(sys.argv[1],'zip',sys.argv[2],sys.argv[3])" \
        "$OUT_DIR/${BUNDLE}" "$STAGE" "$BUNDLE" ) && PACKAGED="python3"
fi
if [ -z "$PACKAGED" ] && have python; then
    ( cd "$STAGE" && python -c "import shutil,sys; shutil.make_archive(sys.argv[1],'zip',sys.argv[2],sys.argv[3])" \
        "$OUT_DIR/${BUNDLE}" "$STAGE" "$BUNDLE" ) && PACKAGED="python"
fi
if [ -z "$PACKAGED" ] && have jar; then
    ( cd "$STAGE" && jar cfM "$ZIP_PATH" "$BUNDLE" ) && PACKAGED="jar"
fi
if [ -z "$PACKAGED" ]; then
    TGZ="$OUT_DIR/${BUNDLE}.tar.gz"
    ( cd "$STAGE" && tar czf "$TGZ" "$BUNDLE" ) && PACKAGED="tar.gz"
    if [ -n "$PACKAGED" ]; then
        warn "No zip/python/jar available -- produced $TGZ instead of .zip."
        warn "Install 'zip' and re-run if a .zip is required, or send the .tar.gz."
        ZIP_PATH="$TGZ"
    fi
fi

if [ -z "$PACKAGED" ] || [ ! -f "$ZIP_PATH" ]; then
    warn "Packaging FAILED. The collected data is in: $ROOT"
    warn "Archive that directory manually and send it for review."
    trap - EXIT
    exit 1
fi

BUNDLE_SHA="$(sha256_of "$ZIP_PATH")"   # for chain of custody

say ""
say "==============================================================="
say " phpocalypse triage complete"
say "==============================================================="
say " VERDICT : $VERDICT"
say " BUNDLE  : $ZIP_PATH"
say " SHA-256 : ${BUNDLE_SHA:-<sha tool unavailable>}"
say "==============================================================="
say ""
say " Next: send the bundle above to your incident-response contact."
say " JUMPSEC clients: upload it via the JSEC portal."
say " Do not delete logs or session files until the review is complete."
say ""

exit 0
