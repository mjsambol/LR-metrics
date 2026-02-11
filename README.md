LRmetrics
=========

LRmetrics is a containerized web application that streamlines and centralizes the collection of Lightrun Management Server diagnostics bundles. After an initial setup, it provides one-click download of diagnostics from multiple Management Servers. It also provides an overview of usage data from the connected servers, both in aggregate and individually. 

In addition to Lightrun Management Servers, users can optionally connect to relevant git repositories. LRmetrics uses *read-only* access to git **history only** to enrich its display of usage data with correlations between end-user use of Lightrun, and subsequent changes to the same code on the same day, which strongly suggest use of Lightrun in the context of a bug which was then fixed.

Recommended usage: Docker
-------------------------
- Exposes HTTP on port `5000`.
- Persists all configuration and downloaded bundles under `/data`, ideally an external folder mapped into the container.
- No external database or services required.

A ready to use image is available at [docker.io/msambol/lr-metrics:latest](https://hub.docker.com/r/msambol/lr-metrics/tags)

You can also build the image from source with:

```bash
docker build -t lr-metrics:latest .
```


Run the container:

```bash
mkdir -p $(pwd)/lrmetrics_data
docker run \
	--name lrmetrics \
	-p 5000:5000 \
	-e FLASK_SECRET="$(openssl rand -hex 32)" \
	-v $(pwd)/lrmetrics_data:/data \
	docker.io/msambol/lr-metrics:latest
```

Replace `docker.io/msambol/lr-metrics:latest` with the appropriate image reference if using a locally built image.


- `FLASK_SECRET` secures the web session. 
- The mounted volume keeps your configuration and downloaded bundles between container restarts.

Once running, visit http://localhost:5001 in your browser.

Data security via the master password 
---------------------------------
- On first visit, LRmetrics asks you to set a master password in the browser. This master password is **never saved to disk anywhere or transmitted to any other system** - it is stored only in memory during your session.
- All connection details (to Lightrun Servers and Github repos) are encrypted using the master password and saved on the volume you mount at `/data`.
- Diagnostic bundles you fetch are saved under `/data/diagnostics_bundles/` and are never automatically transmitted anywhere. The **Extract** button provides easy access to a combined zip with all data, which you can then share manually with your Lightrun Account Manager. 
- When communicating with Lightrun Management Servers, LRmetrics tolerates self-signed certificates.

Kubernetes deployment
---------------------
Manifests are provided under `tools/LRmetrics/kubernetes/` to deploy LRmetrics. 
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



GitHub token permissions
------------------------
- Prefer a fine‑grained personal access token scoped to only the specific repositories you configure.
- Repository permissions: `Contents: Read`.
- **No source code or diff content is fetched** — only commit history basics: author, date, and filenames changed.
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
