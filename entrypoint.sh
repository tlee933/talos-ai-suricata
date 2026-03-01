#!/bin/bash
set -e

echo "Starting AI Suricata services..."

# Start eve_receiver (syslog listener on TCP 5140)
python3 eve_receiver.py &
EVE_PID=$!
echo "eve_receiver started (PID $EVE_PID)"

# Start dashboard (HTTP on 8080)
python3 dashboard.py &
DASH_PID=$!
echo "dashboard started (PID $DASH_PID)"

# Small delay so eve_receiver is ready before ai_suricata starts consuming
sleep 2

# Start ai_suricata (main analysis daemon) in foreground
echo "ai_suricata starting..."
python3 ai_suricata.py &
AI_PID=$!
echo "ai_suricata started (PID $AI_PID)"

# Wait for any child to exit — if one dies, stop all
wait -n
EXIT_CODE=$?
echo "A process exited with code $EXIT_CODE, shutting down..."

kill $EVE_PID $DASH_PID $AI_PID 2>/dev/null || true
wait
exit $EXIT_CODE
