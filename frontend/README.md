# 🎨 Project Quantum - Frontend React Dashboard & UI Guide

The **Project Quantum Frontend** is built using **React 18**, **TypeScript**, **Vite**, and **Tailwind CSS**, providing a real-time, interactive security operations dashboard for Post-Quantum Cryptography (PQC) readiness.

---

## 💻 Tech Stack & UI Design Token System

* **Framework:** React 18 + TypeScript + Vite
* **Styling:** Tailwind CSS (Dark Mode Slate/Zinc palette with neon emerald/cyan/indigo status accents)
* **Icons:** `lucide-react`
* **HTTP Client:** Native `fetch` with typed API service wrapper (`src/services/api.ts`)

---

## 📁 Page Directory & Feature Walkthrough

The UI is organized cleanly into modular page components inside `src/pages/`:

```
src/
├── components/         # Reusable UI widgets, cards, tables, headers, and navbar
│   ├── common/         # PageHeader, MetricCard, StatusBadge, LoadingSpinner
│   ├── dashboard/      # RiskOverviewChart, TopAlgorithmsWidget, TargetSummaryWidget
│   ├── layout/         # Navbar, Sidebar, Footer
│   └── tables/         # FindingsTable, TargetsTable, ScansTable
├── pages/              # Primary view controllers
│   ├── DashboardPage.tsx       # System summary & key metrics
│   ├── TargetsPage.tsx         # Target inventory management
│   ├── ScansPage.tsx           # Scan trigger & execution monitor
│   ├── FindingsPage.tsx        # Cryptographic findings search & filter
│   ├── ApiServerHubPage.tsx    # Bulk API server & OpenAPI spec importer
│   ├── AwsConnectorPage.tsx    # AWS Cloud sync interface
│   ├── AzureConnectorPage.tsx  # Azure Cloud sync interface
│   ├── K8sConnectorPage.tsx    # Kubernetes Cluster audit interface
│   ├── PqcReadinessPage.tsx    # NIST PQC readiness & remediation guide
│   └── ReportsPage.tsx         # Executive Markdown report & CycloneDX 1.6 CBOM export
├── services/           # Backend REST API integration
│   └── api.ts          # Typed fetch requests connecting to http://localhost:8000
└── types/              # TypeScript interfaces & entity types
    └── index.ts        # Target, ScanJob, CryptoFinding, PqcReadinessSummary interfaces
```

---

## 🔌 API Service Layer (`src/services/api.ts`)

All requests route to the FastAPI backend server configured via environment variable or defaulting to `http://localhost:8000/api/v1`.

### Key Service Functions:
* `fetchTargets()`, `createTarget()`, `deleteTarget()`
* `triggerScan()`, `fetchScans()`, `fetchScanDetails()`
* `fetchFindings(filters)`
* `bulkRegisterApiServers()`, `uploadOpenApiSpec()`
* `syncAwsCloud()`, `syncAzureCloud()`, `syncK8sCluster()`
* `fetchPqcReadiness()`, `downloadCbomJson()`, `downloadReportMarkdown()`

---

## 🚀 Running & Building Frontend

### Development Mode (with hot-reload)
```bash
cd frontend
npm install
npm run dev
```
The application will launch on [`http://localhost:5173`](http://localhost:5173).

### Production Build
```bash
npm run build
```
Generates optimized static assets in `frontend/dist/`, which are served via Nginx in Docker deployment mode (`frontend/nginx.conf`).
