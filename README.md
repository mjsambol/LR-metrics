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

Or use an already available build from [Docker hub](https://hub.docker.com/repository/docker/msambol/lr-metrics/general) e.g. [msambol/lr-metrics:20251214](https://hub.docker.com/repository/docker/msambol/lr-metrics/tags/20251214/sha256:916445f34b9877ffb038c8138e88e217fcd0278bfca60618f3690fc429ff9839)

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

Replace `lrmetrics:latest` with the appropriate image reference if not using a locally built image.


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
Below manifests are provided under `tools/LRmetrics/kubernetes/` to deploy LRmetrics. 
You will need an image in a registry accessible by your cluster - see explanation above about building locally or using a build available in Docker Hub, and replace `your-registry/lrmetrics:TAG`.

1) Create a namespace (optional):

```bash
kubectl apply -f kubernetes/namespace.yaml
```

2) Create a Secret with a strong `FLASK_SECRET`:

```bash
kubectl -n lrmetrics create secret generic lrmetrics-secret \
	--from-literal=FLASK_SECRET=$(openssl rand -hex 32)
```

3) Update deployment.yaml with the appropriate image reference. 

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

GitHub token permissions
------------------------
- Prefer a fine‑grained personal access token scoped to only the specific repositories you configure.
- Repository permissions: `Contents: Read`.
- No diff content is fetched — only commit author, date, and filenames changed.
- For GitHub Enterprise, set the API base URL in Setup (e.g., `https://api.github.company.com`).

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
