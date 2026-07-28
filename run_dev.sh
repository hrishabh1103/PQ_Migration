#!/usr/bin/env bash
set -e

echo "=== Starting Enterprise Cryptographic Discovery Platform (Milestone 0) ==="

# 1. Start Backend FastAPI Server
echo "Starting Backend API Server..."
cd backend
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Ensure database schema is migrated via Alembic and port 8000 is free before starting
DATABASE_URL="sqlite:///./dev_qdiscovery.db" PYTHONPATH=. ./venv/bin/alembic upgrade head
lsof -ti:8000 | xargs kill -9 2>/dev/null || true

DATABASE_URL="sqlite:///./dev_qdiscovery.db" uvicorn app.main:app --reload --port 8000 &
BACKEND_PID=$!
cd ..

# 2. Start Frontend Vite Server
echo "Starting Frontend React Dev Server..."
cd frontend
if [ ! -d "node_modules" ]; then
    npm install
fi
npm run dev &
FRONTEND_PID=$!
cd ..

echo "Backend running on http://localhost:8000"
echo "Frontend running on http://localhost:5173"

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT
wait
