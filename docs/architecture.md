# Architecture and operating notes

## Signed scope

The host approval utility creates a lab-only Ed25519 key, enrolls its public key in an OpenSSH allowed-signers file and signs the exact charter bytes in the `charter-scope-v1` namespace. The charter names the approver and operator, limits the time window in UTC, lists allowed and denied origins and path prefixes, and binds the written authorization by SHA-256. The private key stays outside the container mounts. The utility publishes a new bundle by replacing the active pointer after successful signature verification. Someone with write access to the trusted signer file controls this lab's trust root.

The proxy verifies each request against the current signed bytes. It compares the scheme, host, effective port and path segment boundaries. Deny rules take precedence. It forwards an in-scope method, rebuilds the upstream headers from the URL that passed the charter, and limits the capture rate. A TLS tunnel is accepted only when the host and port match an allow rule. Authorization failures are recorded with a URL digest. Missing approval, failed signature verification and an unavailable audit database all prevent forwarding.

The operator chooses the target on the dashboard or with `--url`. Localhost is only the bundled lab. Another origin, such as the public Zero Bank demo at `http://zero.webappsecurity.com/`, is authorized with `python lab.py --operator ID --target URL --approve-target`. The dashboard does not hold the signing key.

## Campaign loop

The engine crawls the chosen origin first, at most twice (`CHARTER_MAX_RECON`, hard cap 2), and records paths, query parameters, and forms in a ledger. It then runs the coverage matrix in code, once per endpoint and check, without another model call. The planner is invoked only after that matrix and may add a few follow-ups (`CHARTER_MAX_FOLLOWUPS`). It cannot repeat recon once the ledger is mapped, and it cannot repeat a check the matrix already ran. Workers still drive one HTTP request, an API check, or ffuf, nuclei, sqlmap, or ZAP when a follow-up asks for them. Those four programs are installed in the image. Every URL is checked before it is sent. Tool output is wrapped as untrusted data, and account secrets are left in the evidence store instead of the next prompt. A finding is proven only when the code binds `proven` to a completed run that already has HTTP evidence. Lab mode skips the approval queue. Any other charter waits for Approve or Deny on the dashboard, including the crawl and the matrix. Turn, request, and token budgets stop the loop.

## Local network

Compose gives the worker access to the capture service on an internal client network. Only the capture service joins both the client and target networks. The database and operator application share an internal storage network with capture. Capture, the dashboard, and the planner also join an egress network so an authorized origin and the model API are reachable. Juice Shop stays on the target network, so the planner cannot bypass the proxy to reach it. A small browser-facing Nginx relay publishes two loopback ports and proxies each to a fixed service. Capture is also published on `127.0.0.1:8080` and Postgres on `127.0.0.1:5432` for a host-side planner. The planner service is behind the `run` profile, so a normal `docker compose up` does not start it.

A person browsing the local target directly can reach the landing page independently of the worker. The charter gate covers captured traffic. The dashboard runs actions for one trusted local operator: capture a chosen URL, start a campaign, and approve or deny a queued step.

## Evidence and persistence

A PostgreSQL transaction creates the run and its allow or deny audit event before forwarding. A second transaction stores the HTTP request, response, optional header finding and completion event together. After a capture-service restart, outstanding runs are marked failed. Compose runs one capture process. Incomplete or blocked runs cannot export a report.

The record preserves ordered header pairs, HTTP version, method and URL, response status, reason and base64-encoded body bytes in each direction. Each body has a SHA-256 digest. These are HTTP application messages as observed by the proxy. TLS framing, TCP packets and transfer-chunk boundaries are outside the capture format. The database and HTML export contain entire bodies. The PDF includes the headers, body lengths and digests so a reviewer can match it to the HTML export. The operator dashboard escapes captured markup before displaying it.

## Operator endpoints

| Endpoint | Result |
| --- | --- |
| `/` | Chosen target, charter status, campaigns, pending approvals, recent runs and audit decisions |
| `POST /actions/capture` | Capture one in-scope URL through the proxy |
| `POST /actions/campaign` | Start an autonomous campaign against the chosen URL |
| `POST /actions/approvals/{id}` | Approve or deny one queued step |
| `/campaigns/{id}` | Campaign status, findings and the runs that produced them |
| `/api/overview` | Totals, current charter and recent runs and events |
| `/runs/{id}` | Run status, finding, remediation and captured exchange |
| `/api/runs/{id}` | Complete evidence, signed scope metadata and audit timeline |
| `/runs/{id}/report.html` | Self-contained HTML report with complete message bodies |
| `/runs/{id}/report.pdf` | Printable engagement report |

## Tests

Use Python 3.13 for the application dependencies. Install `requirements.txt` into a virtual environment and run `python -m unittest discover -s tests -v`. The scope tests use real temporary SSH signatures. The capture tests exercise missing authorization, audit failure, evidence classification, escaped HTML and PDF generation. Campaign tests use a fake origin and a scripted model. The Compose smoke test exercises the actual lab stack. The README contains its command. Model keys stay in `private/compose.env` and are not part of the tests.

## Release boundary

The public repository contains source code, the synthetic lab configuration, tests and demonstration materials. Signed operator bundles, private keys, database credentials, raw private engagements and the owner's planning PDF are excluded from the repository and Docker build context.
