# nerdrc.bash — a conservative, sourceable Bash toolkit for Linux.
# Suggested location: ~/.config/bash/nerdrc.bash
# This file intentionally does NOT change your prompt, shell options, traps,
# umask, history settings, or network state. It adds functions and a private
# loaded-once marker; PATH changes and network access occur only when requested.

# This is Bash-specific; do not source it from /bin/sh.
if [[ -z ${BASH_VERSION:-} ]]; then
    printf '%s\n' 'nerdrc.bash requires Bash.' >&2
    return 1 2>/dev/null || exit 1
fi

# Safe to source more than once in the same shell.
if [[ ${_NERDRC_LOADED:-0} == 1 ]]; then
    return 0
fi
_NERDRC_LOADED=1

# ---------------------------------------------------------------------------
# Navigation
# ---------------------------------------------------------------------------

# Create a directory (including parents) and enter it.
mkcd() {
    if (($# != 1)); then
        printf 'Usage: mkcd DIRECTORY\n' >&2
        return 2
    fi
    command mkdir -p -- "$1" && builtin cd -- "$1"
}

# Move up N directory levels. Defaults to one; caps at 100 to catch typos.
up() {
    local count=${1:-1} i
    if (($# > 1)) || [[ ! $count =~ ^[0-9]+$ ]] || ((${#count} > 3)); then
        printf 'Usage: up [LEVELS (1-100)]\n' >&2
        return 2
    fi
    # Force decimal interpretation, so e.g. 08 is accepted as eight.
    count=$((10#$count))
    if ((count < 1 || count > 100)); then
        printf 'up: LEVELS must be between 1 and 100\n' >&2
        return 2
    fi
    for ((i = 0; i < count; i++)); do
        builtin cd -- .. || return
    done
}

# Enter the top level of the current Git work tree.
croot() {
    local root
    root=$(command git rev-parse --show-toplevel 2>/dev/null) || {
        printf 'croot: not inside a Git work tree\n' >&2
        return 1
    }
    builtin cd -- "$root"
}

# Add an existing directory to PATH only if that exact entry is not present.
# Usage: path_prepend DIRECTORY | path_append DIRECTORY
path_prepend() {
    local dir
    if (($# != 1)) || [[ ! -d $1 ]]; then
        printf 'Usage: path_prepend EXISTING_DIRECTORY\n' >&2
        return 2
    fi
    dir=$1
    case ":${PATH-}:" in
        *":$dir:"*) return 0 ;;
    esac
    PATH="$dir${PATH:+:$PATH}"
    export PATH
}

path_append() {
    local dir
    if (($# != 1)) || [[ ! -d $1 ]]; then
        printf 'Usage: path_append EXISTING_DIRECTORY\n' >&2
        return 2
    fi
    dir=$1
    case ":${PATH-}:" in
        *":$dir:"*) return 0 ;;
    esac
    PATH="${PATH:+$PATH:}$dir"
    export PATH
}

# Display PATH entries one per line, making empty/current-directory entries clear.
fpath() {
    local rest=${PATH-} entry index=0
    if [[ -z ${PATH-} ]]; then
        printf '%s\n' '(PATH is empty; no lookup directories)'
        return 0
    fi
    while [[ $rest == *:* ]]; do
        entry=${rest%%:*}
        if [[ -n $entry ]]; then
            printf '%2d  %s\n' "$index" "$entry"
        else
            printf '%2d  %s\n' "$index" '<empty entry: current directory>'
        fi
        rest=${rest#*:}
        ((index += 1))
    done
    if [[ -n $rest ]]; then
        printf '%2d  %s\n' "$index" "$rest"
    else
        printf '%2d  %s\n' "$index" '<empty entry: current directory>'
    fi
}

# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

# Create a timestamped, metadata-preserving backup beside a file or directory.
# Example: f_bak important.conf -> important.conf.bak.YYYYMMDDTHHMMSS.NNNNNNNNN+0530
f_bak() {
    if (($# != 1)); then
        printf 'Usage: f_bak FILE_OR_DIRECTORY\n' >&2
        return 2
    fi
    if [[ ! -e $1 && ! -L $1 ]]; then
        printf 'f_bak: not found: %s\n' "$1" >&2
        return 1
    fi
    local stamp base target suffix=0
    stamp=$(command date '+%Y%m%dT%H%M%S.%N%z') || return
    base="$1.bak.$stamp"
    target=$base
    while [[ -e $target || -L $target ]]; do
        ((suffix += 1))
        target="$base.$suffix"
    done
    command cp -a -- "$1" "$target"
}

# Extract common archive formats without overwriting existing files where the
# underlying tool supports that policy. Extraction remains an explicit action.
f_extract() {
    if (($# != 1)); then
        printf 'Usage: f_extract ARCHIVE\n' >&2
        return 2
    fi
    local archive=$1
    if [[ ! -f $archive ]]; then
        printf 'f_extract: not a regular file: %s\n' "$archive" >&2
        return 1
    fi
    case $archive in
        *.tar|*.tar.gz|*.tgz|*.tar.bz2|*.tbz|*.tbz2|*.tar.xz|*.txz|*.tar.zst|*.tzst)
            command tar --keep-old-files --no-same-owner --no-same-permissions -xf "$archive"
            ;;
        *.zip)
            # Prefix a leading dash to avoid treating a filename as an option.
            if [[ $archive == -* ]]; then
                archive="./$archive"
            fi
            command unzip -n -- "$archive"
            ;;
        *.gz)
            command gzip -dk -- "$archive"
            ;;
        *.bz2)
            command bzip2 -k -- "$archive"
            ;;
        *.xz)
            command xz -k -- "$archive"
            ;;
        *.zst)
            if ! command -v zstd >/dev/null 2>&1; then
                printf 'f_extract: zstd is required for %s\n' "$archive" >&2
                return 127
            fi
            command zstd -k -d -- "$archive"
            ;;
        *)
            printf 'f_extract: unsupported archive extension: %s\n' "$archive" >&2
            return 2
            ;;
    esac
}

# Print the largest immediate children first. Uses GNU du and sort (normal on Linux).
f_du() {
    local -a pipeline_status
    if (($#)); then
        command du -h --max-depth=1 -- "$@" | command sort -h
    else
        command du -h --max-depth=1 -- . | command sort -h
    fi
    pipeline_status=("${PIPESTATUS[@]}")
    ((pipeline_status[0] == 0 && pipeline_status[1] == 0))
}

# Pretty-print JSON from arguments (files) or stdin using jq.
f_json() {
    if ! command -v jq >/dev/null 2>&1; then
        printf 'f_json: jq is required (install jq to enable this helper)\n' >&2
        return 127
    fi
    command jq . "$@"
}

# Show listening TCP/UDP sockets. ss may show more process details under sudo.
f_ports() {
    if ! command -v ss >/dev/null 2>&1; then
        printf 'f_ports: ss is required (usually provided by iproute2)\n' >&2
        return 127
    fi
    command ss -lntup "$@"
}

# Search shell history with a fixed string by default; regexes are not interpreted.
f_hgrep() {
    if (($# != 1)); then
        printf 'Usage: f_hgrep TEXT\n' >&2
        return 2
    fi
    builtin history | command grep -F -- "$1"
}

# List PATH-resolved command locations without invoking the command.
f_which() {
    if (($# == 0)); then
        printf 'Usage: f_which COMMAND [COMMAND ...]\n' >&2
        return 2
    fi
    local item status=0
    for item in "$@"; do
        if ! command -v "$item"; then
            status=1
        fi
    done
    return "$status"
}

# Show a compact summary of the current machine; this only reads local system data.
f_sysinfo() {
    printf '%s\n' '--- Host ---'
    command hostnamectl 2>/dev/null || {
        printf 'Hostname: '
        command hostname 2>/dev/null || true
        [[ -r /etc/os-release ]] && command sed -n '1,6p' /etc/os-release
    }
    printf '\n%s\n' '--- Kernel ---'
    command uname -a
    printf '\n%s\n' '--- Uptime ---'
    command uptime
    printf '\n%s\n' '--- Memory ---'
    if command -v free >/dev/null 2>&1; then command free -h; fi
    printf '\n%s\n' '--- Filesystems ---'
    command df -hT -x tmpfs -x devtmpfs 2>/dev/null || command df -h
}

# HTTP response headers/status for a URL. Network access happens only when called.
f_http_headers() {
    if (($# != 1)); then
        printf 'Usage: f_http_headers URL\n' >&2
        return 2
    fi
    if ! command -v curl >/dev/null 2>&1; then
        printf 'f_http_headers: curl is required\n' >&2
        return 127
    fi
    command curl --silent --show-error --location \
        --dump-header - --output /dev/null \
        --write-out $'\nHTTP %{http_code} | %{time_total}s | %{url_effective}\n' \
        -- "$1"
}


# A quick built-in index so the toolkit remains discoverable after sourcing.
nerdhelp() {
    cat <<'HELP'
nerdrc.bash — helper index

Navigation
  mkcd DIR             create DIR and enter it
  up [N]               move up N levels (1-100; default 1)
  croot                enter the current Git work-tree root
  path_prepend DIR     add an existing directory to the front of PATH
  path_append DIR      add an existing directory to the end of PATH
  fpath                print PATH entries one per line

Files and data
  f_bak PATH           make a timestamped, metadata-preserving backup
  f_extract ARCHIVE    extract a common archive without overwriting files
  f_du [PATH ...]      show immediate directory sizes, sorted by size
  f_json [FILE ...]    pretty-print JSON using jq (or read stdin)

System and diagnostics
  f_sysinfo            show host, kernel, uptime, memory, and filesystem info
  f_ports [SS-ARGS]    show listening TCP/UDP sockets (uses ss)
  f_topcpu [N]         show the N busiest processes (default 15; max 200)
  f_which CMD ...      resolve command names using Bash's command lookup
  f_hgrep TEXT         search interactive shell history literally
  f_http_headers URL   show HTTP response headers/status with curl

Copy audit logging
  f_cp ARGS...         run cp with the exact arguments, then audit successful
                       local-directory destinations to DEST/.f_copy.mdlog
  f_rsync ARGS...      same idea for rsync; dry-runs/list-only are not logged

Copy logs are JSON arrays containing UTC timestamp, command, source argument
array, destination argument, and the invocation working directory. Python 3 is
used for safely escaped, concurrent, atomic log updates. Unknown/unsupported
option layouts are still passed to cp/rsync unchanged, but may skip logging.
The toolkit does not redefine cp, rsync, ls, rm, or other standard commands.
HELP
}

# ---------------------------------------------------------------------------
# Copy wrappers with a JSON audit log
# ---------------------------------------------------------------------------
# f_cp and f_rsync invoke the real programs with the exact original arguments.
# After a successful operation, they log the original source argument(s), the
# original destination argument, the command, timestamp, and invocation cwd to
# DEST/.f_copy.mdlog when DEST is a local directory.
#
# The log is a JSON array. Python 3 is used only for robust JSON escaping and
# serialized/atomic updates; the copy operation itself does not depend on Python.
# A sidecar .lock file coordinates concurrent writers. Malformed logs are not
# silently overwritten. If logging fails, a warning is printed but the copy's
# own exit status is preserved.

# Parser state returned by _nerdrc_parse_cp / _nerdrc_parse_rsync:
#   _NERDRC_DEST, _NERDRC_COPY_SOURCES (array), _NERDRC_DRYRUN
_nerdrc_parse_cp() {
    local -a args=("$@") operands=()
    local i=0 arg rest ch target_dir='' no_target=0
    _NERDRC_DEST=''
    _NERDRC_COPY_SOURCES=()
    _NERDRC_DRYRUN=0
    local parse_ok=1 end_options=0

    while ((i < ${#args[@]})); do
        arg=${args[i]}
        if ((end_options)); then
            operands+=("$arg")
            ((i += 1))
            continue
        fi
        case $arg in
            --)
                end_options=1
                ((i += 1))
                continue
                ;;
            --target-directory=*)
                target_dir=${arg#*=}
                ;;
            --target-directory|-t)
                ((i += 1))
                if ((i >= ${#args[@]})); then parse_ok=0; break; fi
                target_dir=${args[i]}
                ;;
            --no-target-directory|-T)
                no_target=1
                ;;
            --suffix|--sparse)
                ((i += 1))
                if ((i >= ${#args[@]})); then parse_ok=0; break; fi
                ;;
            --suffix=*|--sparse=*|--backup|--backup=*|--preserve|--preserve=*|--no-preserve=*|--reflink|--reflink=*|--context|--context=*)
                ;;
            --archive|--attributes-only|--copy-contents|--debug|--dereference|--force|--interactive|--link|--no-clobber|--no-dereference|--parents|--recursive|--remove-destination|--symbolic-link|--strip-trailing-slashes|--update|--verbose|--one-file-system|--help|--version)
                ;;
            --*)
                # Unknown option: keep the real cp invocation untouched, but
                # do not guess at its operand layout for logging.
                parse_ok=0
                ;;
            -)
                operands+=("$arg")
                ;;
            -?*)
                rest=${arg:1}
                while [[ -n $rest ]]; do
                    ch=${rest:0:1}
                    rest=${rest:1}
                    case $ch in
                        t|S)
                            if [[ -n $rest ]]; then
                                if [[ $ch == t ]]; then target_dir=$rest; fi
                                rest=''
                            else
                                ((i += 1))
                                if ((i >= ${#args[@]})); then parse_ok=0; break; fi
                                if [[ $ch == t ]]; then target_dir=${args[i]}; fi
                            fi
                            break
                            ;;
                        T) no_target=1 ;;
                        a|b|d|f|i|l|n|p|r|s|u|v|x|H|L|P|R|Z)
                            ;;
                        *) parse_ok=0; rest='' ;;
                    esac
                done
                ;;
            *)
                operands+=("$arg")
                ;;
        esac
        ((i += 1))
    done

    ((parse_ok)) || return 1
    ((no_target == 0)) || return 1
    if [[ -n $target_dir ]]; then
        ((${#operands[@]} >= 1)) || return 1
        _NERDRC_DEST=$target_dir
        _NERDRC_COPY_SOURCES=("${operands[@]}")
    else
        ((${#operands[@]} >= 2)) || return 1
        _NERDRC_DEST=${operands[${#operands[@]}-1]}
        _NERDRC_COPY_SOURCES=("${operands[@]:0:${#operands[@]}-1}")
    fi
}

_nerdrc_parse_rsync() {
    local -a args=("$@") operands=()
    local i=0 arg rest ch parse_ok=1 end_options=0
    _NERDRC_DEST=''
    _NERDRC_COPY_SOURCES=()
    _NERDRC_DRYRUN=0

    while ((i < ${#args[@]})); do
        arg=${args[i]}
        if ((end_options)); then
            operands+=("$arg")
            ((i += 1))
            continue
        fi
        if [[ $arg == -- ]]; then
            end_options=1
            ((i += 1))
            continue
        fi
        if [[ $arg == --dry-run || $arg == --list-only || $arg == --dry-run=* ]]; then
            _NERDRC_DRYRUN=1
            ((i += 1))
            continue
        fi
        if [[ $arg == --*=* ]]; then
            # Only accept known value-taking long options here. For an unknown
            # option, preserve rsync's exact invocation but skip audit logging.
            case ${arg%%=*} in
                --address|--backup-dir|--block-size|--bwlimit|--checksum-seed|--chmod|--chown|--compare-dest|--copy-dest|--exclude|--exclude-from|--files-from|--filter|--groupmap|--include|--include-from|--iconv|--link-dest|--log-file|--log-file-format|--max-delete|--max-size|--min-size|--modify-window|--out-format|--partial-dir|--password-file|--port|--protocol|--read-batch|--rsync-path|--rsh|--sockopts|--suffix|--temp-dir|--timeout|--user|--usermap|--write-batch|--stop-after|--stop-at|--contimeout|--info|--debug|--skip-compress|--compress-level|--max-alloc|--checksum-seed)
                    ;;
                *) parse_ok=0 ;;
            esac
            ((i += 1))
            continue
        fi
        case $arg in
            --address|--backup-dir|--block-size|--bwlimit|--checksum-seed|--chmod|--chown|--compare-dest|--copy-dest|--exclude|--exclude-from|--files-from|--filter|--groupmap|--include|--include-from|--iconv|--link-dest|--log-file|--log-file-format|--max-delete|--max-size|--min-size|--modify-window|--out-format|--partial-dir|--password-file|--port|--protocol|--read-batch|--rsync-path|--rsh|--sockopts|--suffix|--temp-dir|--timeout|--user|--usermap|--write-batch|--stop-after|--stop-at|--contimeout|--info|--debug|--skip-compress|--compress-level|--max-alloc)
                ((i += 1))
                if ((i >= ${#args[@]})); then parse_ok=0; break; fi
                ;;
            --archive|--recursive|--relative|--no-relative|--dirs|--links|--copy-links|--copy-unsafe-links|--safe-links|--munge-links|--copy-dirlinks|--keep-dirlinks|--hard-links|--perms|--executability|--acls|--xattrs|--owner|--group|--devices|--specials|--times|--omit-dir-times|--omit-link-times|--checksum|--one-file-system|--whole-file|--no-whole-file|--sparse|--existing|--ignore-existing|--ignore-non-existing|--update|--inplace|--append|--append-verify|--delete|--delete-before|--delete-during|--delete-delay|--delete-after|--delete-excluded|--ignore-errors|--force|--remove-source-files|--delete-missing-args|--ignore-missing-args|--partial|--delay-updates|--prune-empty-dirs|--ignore-times|--size-only|--ipv4|--ipv6|--quiet|--verbose|--progress|--human-readable|--8-bit-output|--itemize-changes|--stats|--compress|--cvs-exclude|--from0|--mkpath|--no-motd|--no-iconv|--no-implied-dirs|--no-perms|--no-owner|--no-group|--no-times|--no-acls|--no-xattrs|--no-links|--no-hard-links|--no-devices|--no-specials|--no-compress|--no-whole-file|--no-inc-recursive|--no-blocking-io|--blocking-io|--omit-dir-times|--omit-link-times|--checksum|--exclude-from=*)
                ;;
            --*)
                # Unknown option: safest is to skip logging rather than guess.
                parse_ok=0
                ;;
            -)
                operands+=("$arg")
                ;;
            -?*)
                rest=${arg:1}
                while [[ -n $rest ]]; do
                    ch=${rest:0:1}
                    rest=${rest:1}
                    case $ch in
                        B|e|f|M|T)
                            if [[ -z $rest ]]; then
                                ((i += 1))
                                if ((i >= ${#args[@]})); then parse_ok=0; break; fi
                            fi
                            rest=''
                            break
                            ;;
                        n) _NERDRC_DRYRUN=1 ;;
                        a|A|b|c|C|D|F|g|G|H|h|i|I|k|K|l|L|m|o|O|p|P|q|r|R|s|t|u|v|w|W|x|X|y|z|4|6|8|E|J|N|S|U|Y)
                            ;;
                        *) parse_ok=0; rest='' ;;
                    esac
                done
                ;;
            *)
                operands+=("$arg")
                ;;
        esac
        ((i += 1))
    done

    ((parse_ok)) || return 1
    ((${#operands[@]} >= 2)) || return 1
    _NERDRC_DEST=${operands[${#operands[@]}-1]}
    _NERDRC_COPY_SOURCES=("${operands[@]:0:${#operands[@]}-1}")
}

_nerdrc_log_copy() {
    local log_dir=$1 command_name=$2 destination=$3 invocation_cwd=$4
    shift 4
    local log_file="$log_dir/.f_copy.mdlog"

    if ! command -v python3 >/dev/null 2>&1; then
        printf 'nerdrc: copy succeeded, but logging needs python3; no log written\n' >&2
        return 1
    fi

    command python3 - "$log_file" "$command_name" "$destination" "$invocation_cwd" "$@" <<'PY'
import datetime
import fcntl
import json
import os
import stat
import sys
import tempfile

log_path, command_name, destination, cwd, *sources = sys.argv[1:]
log_dir = os.path.dirname(log_path) or "."
lock_path = log_path + ".lock"

try:
    # Do not follow a symlink or replace one at the expected log path.
    if os.path.islink(log_path):
        raise RuntimeError(f"refusing to update symlink log: {log_path}")

    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(lock_fd, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as stream:
                records = json.load(stream)
            if not isinstance(records, list):
                raise ValueError("existing log is valid JSON but is not an array")
            mode = stat.S_IMODE(os.stat(log_path, follow_symlinks=False).st_mode)
        else:
            records = []
            mode = 0o600

        records.append({
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
                .isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "command": command_name,
            "sources": sources,
            "destination": destination,
            "cwd": cwd,
        })

        fd, temporary_path = tempfile.mkstemp(prefix=".f_copy.mdlog.", dir=log_dir)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(records, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, log_path)
            try:
                dir_fd = os.open(log_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        except BaseException:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise
except Exception as exc:
    print(f"nerdrc: copy succeeded, but could not update {log_path}: {exc}", file=sys.stderr)
    sys.exit(1)
PY
}

f_cp() {
    local invocation_cwd=$PWD parse_status copy_status dest
    local -a sources=()
    if _nerdrc_parse_cp "$@"; then
        parse_status=0
    else
        parse_status=$?
    fi
    dest=$_NERDRC_DEST
    sources=("${_NERDRC_COPY_SOURCES[@]}")

    command cp "$@"
    copy_status=$?
    if ((copy_status == 0 && parse_status == 0)) && [[ -n $dest && -d $dest ]]; then
        _nerdrc_log_copy "$dest" f_cp "$dest" "$invocation_cwd" "${sources[@]}" || true
    fi
    return "$copy_status"
}

f_rsync() {
    local invocation_cwd=$PWD parse_status copy_status dest
    local -a sources=()
    if _nerdrc_parse_rsync "$@"; then
        parse_status=0
    else
        parse_status=$?
    fi
    dest=$_NERDRC_DEST
    sources=("${_NERDRC_COPY_SOURCES[@]}")
    local dry_run=$_NERDRC_DRYRUN

    command rsync "$@"
    copy_status=$?
    if ((copy_status == 0 && parse_status == 0 && dry_run == 0)) && [[ -n $dest && -d $dest ]]; then
        _nerdrc_log_copy "$dest" f_rsync "$dest" "$invocation_cwd" "${sources[@]}" || true
    fi
    return "$copy_status"
}

# A final convenience: show the most CPU-heavy processes (GNU ps/coreutils).
f_topcpu() {
    local count=${1:-15}
    if (($# > 1)) || [[ ! $count =~ ^[0-9]+$ ]] || ((${#count} > 3)); then
        printf 'Usage: f_topcpu [LINES (1-200)]\n' >&2
        return 2
    fi
    count=$((10#$count))
    if ((count < 1 || count > 200)); then
        printf 'Usage: f_topcpu [LINES (1-200)]\n' >&2
        return 2
    fi
    command ps -eo pid,ppid,stat,%cpu,%mem,etime,comm --sort=-%cpu | command head -n "$((count + 1))"
}
