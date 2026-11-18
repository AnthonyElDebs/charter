# Architecture and operating notes

## Signed scope

The host approval utility creates a lab-only Ed25519 key, enrolls its public key in an OpenSSH allowed-signers file and signs the exact charter bytes in the `charter-scope-v1` namespace. The charter names the approver and operator, limits the time window in UTC, lists allowed and denied origins and path prefixes, and binds the written authorization by SHA-256. The private key stays outside the container mounts. The utility publishes a new bundle by replacing the active pointer after successful signature verification. Someone with write access to the trusted signer file controls this lab's trust root.

The proxy verifies each request against the current signed bytes. It compares the scheme, host, effective port and path segment boundaries. Deny rules take precedence. It then enforces the bundled demo's stricter one-page, anonymous GET policy, and constructs the upstream headers. The capture service limits accepted requests to one per second. It runs mitmproxy with lazy upstream connections and refuses tunnels. Authorization failures are recorded with a URL digest. Missing approval, failed signature verification and an unavailable audit database all prevent forwarding.

## Local network

Compose gives the worker access to the capture service on an internal client network. Only the capture service joins both the client and target networks. The database and operator application share an internal storage network with capture. A small browser-facing Nginx relay publishes two loopback ports and proxies each to a fixed service. Only this relay joins the entry network. The worker, target, database, capture service and dashboard have internal networks exclusively. Downloading images and building dependencies requires internet access on the Docker host.

A person browsing the local target directly can reach the landing page independently of the worker. The charter gate covers the worker's traffic. The dashboard is read-only and intended for a trusted local workstation.

## Evidence and persistence

A PostgreSQL transaction creates the run and its allow or deny audit event before forwarding. A second transaction stores the HTTP request, response, optional header finding and completion event together. After a capture-service restart, outstanding runs are marked failed. Compose runs one capture process. Incomplete or blocked runs cannot export a report.

The record preserves ordered header pairs, HTTP version, method and URL, response status, reason and base64-encoded body bytes in each direction. Each body has a SHA-256 digest. These are HTTP application messages as observed by the proxy. TLS framing, TCP packets and transfer-chunk boundaries are outside the capture format. The database and HTML export contain entire bodies. The PDF includes the headers, body lengths and digests so a reviewer can match it to the HTML export. The operator dashboard escapes captured markup before displaying it.

## Operator endpoints

| Endpoint | Result |
| --- | --- |
| `/` | Current charter status, recent runs and audit decisions, refreshed every ten seconds |
| `/api/overview` | Totals, current charter and 100 most recent runs and events |
| `/runs/{id}` | Run status, finding, remediation and captured exchange |
| `/api/runs/{id}` | Complete evidence, signed scope metadata and audit timeline |
| `/runs/{id}/report.html` | Self-contained HTML report with complete message bodies |
| `/runs/{id}/report.pdf` | Printable engagement report |

## Tests

Use Python 3.13 for the application dependencies. Install `requirements.txt` into a virtual environment and run `python -m unittest discover -s tests -v`. The scope tests use real temporary SSH signatures. The capture tests exercise missing authorization, audit failure, evidence classification, escaped HTML and PDF generation. The Compose smoke test exercises the actual lab stack. The README contains its command.

## Release boundary

The public repository contains source code, the synthetic lab configuration, tests and demonstration materials. Signed operator bundles, private keys, database credentials, raw private engagements and the owner's planning PDF are excluded from the repository and Docker build context.
