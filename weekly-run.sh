#!/usr/bin/env bash
# weekly-run.sh — full defensive workbench pipeline for one target.
# ctwatch -> collect -> analyze -> diff -> assess. Run ID is resolved from
# the ledger scoped to the target, so the cron never has to guess it.
# Any in-scope target works: ./weekly-run.sh example.com
set -euo pipefail
cd "$(dirname "$0")"
TARGET="${1:-marcusrichards.dev}"

python3 -m workbench.cli ctwatch
python3 -m workbench.cli collect --target "$TARGET"
RUN_ID=$(python3 -c 'import sqlite3,sys; t=sys.argv[1]; print(sqlite3.connect("workbench.db").execute("select max(id) from runs where target=?", (t,)).fetchone()[0])' "$TARGET")
python3 -m workbench.cli analyze --run "$RUN_ID"
python3 -m workbench.cli diff --run "$RUN_ID"
python3 -m workbench.cli assess --run "$RUN_ID"
echo "WEEKLY_RUN_DONE run_id=$RUN_ID target=$TARGET"
