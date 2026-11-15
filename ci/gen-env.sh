#!/bin/bash
# shellcheck disable=SC2034 # PASSWORD etc. are read via ${!var_name}.
##Generates the .env file the install script needs, for a CI test profile.
##Usage: gen-env.sh <profile.sh> <output.env>
##Optional environment: CI_ADMIN_PUBKEY_FILE -- public key to install as admin_ssh_pubkeys.
##
##Layers, later wins: defaults parsed from buildenv() in the install script, then random
##PASSWORD / zfs_root_password / admin_ssh_pubkeys, then the profile.
##Fails if the result doesn't define every name in the script's ENV_VAR_ORDER, so an
##env variable added to the script without a default is caught here, not mid-install.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="${CI_SCRIPT:-$here/../debian_server_encrypted_root_zfs.sh}"
profile="${1:?usage: gen-env.sh <profile.sh> <output.env>}"
out="${2:?usage: gen-env.sh <profile.sh> <output.env>}"

rand_hex(){ od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

env_var_order="$(sed -n '/^ENV_VAR_ORDER="/,/"$/p' "$script" | sed -e '1s/^ENV_VAR_ORDER="//' -e '$s/"$//')"
[ -n "$env_var_order" ] || { echo "Could not find ENV_VAR_ORDER in ${script}." >&2; exit 1; }

##The single-line  name="value"  defaults at the top of buildenv(), up to its first real statement.
defaults="$(awk '/^buildenv\(\)\{/{f=1;next} f&&/^\tif \[ -f "\$env_file" \]/{exit} f' "$script" \
	| sed -nE 's/^\t([A-Za-z_][A-Za-z0-9_]*="[^"]*").*/\1/p')"
[ -n "$defaults" ] || { echo "Could not extract buildenv() defaults from ${script}." >&2; exit 1; }

##A profile may only set real env variables or CI_* harness settings -- a typo'd name would
##otherwise be silently ignored.
while read -r profile_var;
do
	case " $env_var_order " in
		*[[:space:]]"$profile_var"[[:space:]]*) ;;
		*)
			case "$profile_var" in
				CI_*) ;;
				*) echo "${profile}: ${profile_var} is not in ENV_VAR_ORDER (and isn't a CI_* setting)." >&2; exit 1 ;;
			esac
		;;
	esac
done < <(grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$profile" | tr -d '=')

tmp_out="$(mktemp "${out}.XXXXXX")"
trap 'rm -f "$tmp_out"' EXIT

(
	set -euo pipefail
	eval "$defaults"

	PASSWORD="$(rand_hex 12)"
	zfs_root_password="$(rand_hex 12)"
	admin_ssh_pubkeys=""
	if [ -n "${CI_ADMIN_PUBKEY_FILE-}" ];
	then
		admin_ssh_pubkeys="$(cat "$CI_ADMIN_PUBKEY_FILE")"
	fi

	# shellcheck source=/dev/null
	. "$profile"

	missing=""
	for var_name in $env_var_order;
	do
		[ -n "${!var_name+x}" ] || missing="${missing} ${var_name}"
	done
	if [ -n "$missing" ];
	then
		echo "No default or profile value for:${missing}" >&2
		exit 1
	fi

	for var_name in $env_var_order;
	do
		printf '%s=%q\n' "$var_name" "${!var_name}"
	done
) > "$tmp_out"

chmod 600 "$tmp_out"
mv "$tmp_out" "$out"
trap - EXIT
echo "Wrote ${out} from profile $(basename "$profile")."
