#!/bin/sh
# The pre push gate. Every step writes its stdout to .check/<step>.out and its exit code to
# .check/<step>.exit, and the summary is read from the exit FILES. A verification result is never
# the status of a compound command: three exit codes were misread through pipes in one week, once
# reporting a kill test as clean when it had exited 1.
cd "$(dirname "$0")/.." || exit 2
mkdir -p .check
SHA=$(git rev-parse --short=12 HEAD)
POPPY_SCAN="${POPPY_SCAN:?set POPPY_SCAN to the private reference scan script}"
run() { name="$1"; shift; "$@" > ".check/$name.out" 2>&1; echo $? > ".check/$name.exit"; printf "  %-14s exit %s\n" "$name" "$(cat ".check/$name.exit")"; }
echo "pre push gate at $SHA"
run clean    sh -c '[ -z "$(git status --porcelain)" ]'
run test     npm test
run spec     npm run spec-status
# The private reference scan lives OUTSIDE this repository, because its patterns name the private
# things. A copy here matched itself and failed its own gate on the first run. Absent, the step
# fails rather than passes: a scan that cannot run is not a scan that passed.
run scan     sh -c '[ -x "$POPPY_SCAN" ] && "$POPPY_SCAN" . >/dev/null; [ $? -eq 1 ]'
ok=1; for f in .check/*.exit; do [ "$(cat "$f")" = "0" ] || ok=0; done
if [ "$ok" = 1 ]; then touch ".check/$SHA.ok"; echo "all exit files read 0: .check/$SHA.ok written"; else echo "a step did not exit 0: no .ok written"; exit 1; fi
