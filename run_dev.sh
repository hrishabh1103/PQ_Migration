#!/usr/bin/env bash
set -e

echo "=== Starting Enterprise Cryptographic Discovery Platform ==="

# 1. Kill anything on our ports
echo "Clearing ports 8000 and 5173..."
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
lsof -ti:5173 | xargs kill -9 2>/dev/null || true
sleep 1

# 2. Start Backend FastAPI Server
echo "Starting Backend API Server..."
cd backend
if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Run Alembic migrations
DATABASE_URL="sqlite:///./dev_qdiscovery.db" PYTHONPATH=. ./venv/bin/alembic upgrade head

# Start uvicorn with reload
DATABASE_URL="sqlite:///./dev_qdiscovery.db" PYTHONPATH=. uvicorn app.main:app --reload --port 8000 &
BACKEND_PID=$!
cd ..

# 3. Start Frontend Vite Server
echo "Starting Frontend React Dev Server..."
cd frontend
if [ ! -d "node_modules" ]; then
    npm install
fi
npm run dev -- --port 5173 &
FRONTEND_PID=$!
cd ..

echo ""
echo "======================================"
echo "Backend  → http://localhost:8000"
echo "Frontend → http://localhost:5173"
echo "API Docs → http://localhost:8000/docs"
echo "======================================"
echo "Press Ctrl+C to stop both servers"

trap "echo 'Shutting down...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" EXIT INT TERM
wait
