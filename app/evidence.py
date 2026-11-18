from base64 import b64encode
from hashlib import sha256


def message(message):
    body = message.raw_content
    if body is None:
        raise ValueError("missing message body")
    return {"http_version": message.http_version,
            "headers": [[name.decode("latin1"), value.decode("latin1")] for name, value in message.headers.fields],
            "body_base64": b64encode(body).decode("ascii"), "body_bytes": len(body),
            "body_sha256": sha256(body).hexdigest()}


def capture(flow):
    req, res = flow.request, flow.response
    return {"request": {**message(req), "method": req.method, "url": req.url, "path": req.path},
            "response": {**message(res), "status": res.status_code, "reason": res.reason}}


def assess(evidence):
    response = evidence["response"]
    headers = {name.lower(): value for name, value in response["headers"]}
    mime = headers.get("content-type", "").split(";")[0].strip().lower()
    if response["status"] == 200 and mime == "text/html" and "content-security-policy" not in headers:
        return {"title": "Landing page omits the Content-Security-Policy header", "severity": "Low",
                "evidence": "The HTTP 200 HTML response contains no Content-Security-Policy header.",
                "impact": "Browsers receive no response-header policy restricting script sources on this page. "
                          "This observation alone does not demonstrate script execution. An HTML meta policy may also apply.",
                "reproduce": "Within the approved local lab, request the landing page and inspect the response headers.",
                "remediation": "Inventory the scripts this page needs, test a restrictive policy in report-only mode, "
                               "then deploy the verified policy as an enforcing response header."}
    return None
