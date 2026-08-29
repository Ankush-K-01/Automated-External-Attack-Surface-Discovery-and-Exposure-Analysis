"""Fast & non-blocking Asset Classifier."""
import logging
import socket
import ssl

logger = logging.getLogger(__name__)

def probe_http_fast(host: str, port: int) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=0.5)
        sock.close()
        return True
    except Exception:
        return False

def classify(host: str | None, port: int | None, endpoints: list[str] = []) -> str:
    h = (host or "").lower()
    paths = " ".join(endpoints).lower()

    if any(x in h for x in ("s3.", "blob.core.", "storage.googleapis.", "amazonaws.com")):
        return "CLOUD_STORAGE"
    if port in (25, 465, 587):
        return "MAIL_SERVER"
    if port in (53,):
        return "DNS_INFRA"

    if port in (80, 443, 8080, 8443):
        if any(x in paths for x in ("/api/", "/v1/", "/v2/", "/graphql", "/openapi", "/swagger")):
            return "API_ENDPOINT"
        if "api." in h or "-api" in h:
            return "API_ENDPOINT"
        return "WEB_APP"

    return "UNKNOWN_SERVICE"
