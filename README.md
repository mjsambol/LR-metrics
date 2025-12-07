LRmetrics
=========

LRmetrics is a small Flask web app that helps you collect usage and diagnostics bundles from Lightrun servers, view summaries, and export bundles.

Recommended usage: Docker
-------------------------
- Exposes HTTP on port `5000`.
- Persists all configuration and downloaded bundles under `/data` inside the container.
- No external database or services required.

Build the image:

```bash
docker build -t lrmetrics:latest .
```

Run the container (recommended):

```bash
mkdir -p $(pwd)/lrmetrics_data
docker run \
	--name lrmetrics \
	-p 5000:5000 \
	-e FLASK_SECRET="$(openssl rand -hex 32)" \
	-v $(pwd)/lrmetrics_data:/data \
	lrmetrics:latest
```

- `FLASK_SECRET` secures the web session. Always set it in production.
- The mounted volume keeps your configuration and downloaded bundles between container restarts.

Master password and data security
---------------------------------
- On first visit, LRmetrics asks you to set a master password in the browser. This master password is stored only in your session.
- Server credentials you enter on the Setup page are encrypted locally using the master password and saved in `/data/servers.json`.
- The master password is never written to disk or transmitted to any other system.
- Diagnostic bundles you fetch are saved under `/data/diagnostics_bundles/` and are never automatically uploaded anywhere.

Kubernetes deployment
---------------------
Below manifests are provided under `tools/LRmetrics/kubernetes/` to deploy LRmetrics. You will need an image in a registry accessible by your cluster (replace `your-registry/lrmetrics:TAG`).

1) Build and push the image:

```bash
docker build -t your-registry/lrmetrics:TAG .
docker push your-registry/lrmetrics:TAG
```

2) Create a namespace (optional):

```bash
kubectl apply -f kubernetes/namespace.yaml
```

3) Create a Secret with a strong `FLASK_SECRET`:

```bash
kubectl -n lrmetrics create secret generic lrmetrics-secret \
	--from-literal=FLASK_SECRET=$(openssl rand -hex 32)
```

4) Apply storage, deployment, and service:

```bash
kubectl -n lrmetrics apply -f kubernetes/pvc.yaml
kubectl -n lrmetrics apply -f kubernetes/deployment.yaml
kubectl -n lrmetrics apply -f kubernetes/service.yaml
```

5) Access the app:
- Port-forward:

```bash
kubectl -n lrmetrics port-forward svc/lrmetrics 8080:5000
```

Visit http://localhost:8080

- Or deploy an Ingress (optional):

```bash
kubectl -n lrmetrics apply -f kubernetes/ingress.yaml
```

Security and privacy notes
--------------------------
- LRmetrics tolerates self-signed certificates when contacting your Lightrun servers to simplify on-prem usage.
- All configuration data stays on the volume you mount at `/data`.
- Diagnostic bundles are stored locally and are not transmitted automatically. Download and share them manually if needed.

Development only
----------------
Local development helpers are provided via `run.sh`.

```bash
# Create a virtualenv and run locally on port 5000
./run.sh run-dev

# Rebuild the Docker image from this folder
./run.sh build

# Run the built container, mounting a local data folder
./run.sh run --mount $(pwd)/lrmetrics_data
```

In development, the app uses a default session secret if `FLASK_SECRET` is not provided. Do not use this default in production.
