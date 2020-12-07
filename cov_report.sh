#!/usr/bin/env sh

# This script will use your default ${GOROOT}
# and ${GOPATH}, so ensure these locations exist,
# and "${GOPATH}/bin" is in your default ${PATH}.

# NOTE: This script is known to work on bash, zsh,
# and ksh (ksh93 and ksh2000+), but it is not
# POSIX compliant, due to the using the ksh-derived
# "type" utility. If you are not able to use this
# script, the tools are easily accessible and manual
# runs should be straight-forward on most platforms.

# Abort and inform in the case of csh or tcsh as sh.
# shellcheck disable=SC2046,SC2006,SC2116,SC2065
test _$(echo asdf 2>/dev/null) != _asdf >/dev/null &&
	printf '%s\n' "Error: csh as sh is unsupported." &&
	exit 1

cleanUp() {
	printf '\n%s\n' "Running cleanup tasks." >&2 || true :
	set +u >/dev/null 2>&1 || true :
	set +e >/dev/null 2>&1 || true :
	rm -f ./gocov_report_goc25519sm.html >/dev/null 2>&1 || true:
	printf '%s\n' "All cleanup tasks completed." >&2 || true :
	printf '%s\n' "" || true :
}

global_trap() {
	err=${?}
	trap - EXIT
	trap '' EXIT INT TERM ABRT ALRM HUP
	cleanUp
}
trap 'global_trap $?' EXIT
trap 'err=$?; global_trap; exit $?' ABRT ALRM HUP TERM
trap 'err=$?; trap - EXIT; global_trap $err; exit $err' QUIT
trap 'global_trap; trap - INT; kill -INT $$; sleep 1; trap - TERM; kill -TERM $$' INT
trap '' EMT IO LOST SYS URG >/dev/null 2>&1 || true :

set -o pipefail >/dev/null 2>&1
if [ ! -f "./.goc25519sm_root" ]; then
	printf '\n%s\n' "You must run this tool from the root directory" >&2
	printf '%s\n' "of your local goc25519sm source tree or checkout." >&2
	exit 1 || :
fi

export CGO_ENABLED=1
export TEST_TAGS='-tags=amd64,purego'
export TEST_FLAGS="${TEST_TAGS} -count=1 -covermode=atomic -cover -cpu=1 -parallel=1 -race -trimpath"
export GOFLAGS='-tags=osnetgo,osusergo'
# shellcheck disable=SC2155
export GOC_TARGETS="$(go list ./... | grep -v test | sort | uniq)"

type gocov 1>/dev/null 2>&1 # shellcheck disable=SC2181
if [ "${?}" -ne 0 ]; then
	printf '\n%s\n' "This script requires the gocov tool." >&2
	printf '%s\n' "You may obtain it with the following command:" >&2
	printf '%s\n\n' "\"go get github.com/axw/gocov/gocov\"" >&2
	exit 1 || :
fi

cleanUp || true &&
	unset="Error: Testing flags are unset, aborting." &&
	export unset
# shellcheck disable=SC2086
(
	date 2>/dev/null
	gocov test ${TEST_FLAGS:?${unset:?}} ${GOC_TARGETS} >gocov_report_goc.json &&
		gocov report <gocov_report_goc.json >gocov_report_goc.txt
) ||
	{
		printf '\n%s\n' "gocov failed complete successfully." >&2
		exit 1 || :
	}
# shellcheck disable=SC2086

type gocov-html 1>/dev/null 2>&1 # shellcheck disable=SC2181
if [ "${?}" -ne 0 ]; then
	printf '%\n%s\n' "This script optionally utilizes gocov-html." >&2
	printf '%s\n' "You may obtain it with the following command:" >&2
	printf '%s\n\n' "\"go get https://github.com/matm/gocov-html\"" >&2
	exit 1 || :
fi
(gocov-html <gocov_report_goc.json >gocov_report_goc.html) ||
	{
		printf '\n%s\n' "gocov-html failed to complete successfully." >&2
		exit 1 || :
	}

if [ -x "${HOME}/.goc25519sm.cov.local" ]; then
	printf '%s\n' "Local script started"
	(exec "${HOME}"/.goc25519sm.cov.local)
	printf '%s\n' "Local script ended"
fi

mkdir -p ./cov && mv -f ./gocov_report_* ./cov &&
	printf '\n%s\n' "Done - output is located at ./cov"