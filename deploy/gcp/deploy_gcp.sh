#!/bin/bash
set -e

PROJECT_ID=${GCP_PROJECT_ID:-"pqc-discovery-prod"}
REGION=${GCP_REGION:-"us-central1"}
SERVICE_NAME="qdiscovery-platform"

echo "=== Packaging & Deploying Q-Discovery Platform to GCP Cloud Servers ==="
echo "Project ID: $PROJECT_ID | Region: $REGION"

# Enable required APIs
gcloud services enable artifactregistry.googleapis.com run.googleapis.com sqladmin.googleapis.com --project="$PROJECT_ID"

# Build & Push Backend Container
echo "Building Backend Container Image..."
gcloud builds submit backend/ --tag "gcr.io/$PROJECT_ID/qdiscovery-backend:latest" --project="$PROJECT_ID"

# Build & Push Frontend Container
echo "Building Frontend Container Image..."
gcloud builds submit frontend/ --tag "gcr.io/$PROJECT_ID/qdiscovery-frontend:latest" --project="$PROJECT_ID"

# Deploy Backend to Cloud Run
echo "Deploying Backend service to Cloud Run..."
gcloud run deploy "$SERVICE_NAME-backend" \
  --image "gcr.io/$PROJECT_ID/qdiscovery-backend:latest" \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --project="$PROJECT_ID"

# Deploy Frontend to Cloud Run
echo "Deploying Frontend service to Cloud Run..."
gcloud run deploy "$SERVICE_NAME-frontend" \
  --image "gcr.io/$PROJECT_ID/qdiscovery-frontend:latest" \
  --region "$REGION" \
  --platform managed \
  --allow-unauthenticated \
  --project="$PROJECT_ID"

echo "=== Deployment to GCP Cloud Servers Complete ==="
