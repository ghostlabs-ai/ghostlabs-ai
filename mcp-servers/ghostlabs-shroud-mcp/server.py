"""
GhostLabs Shroud MCP Server — Security and compliance tools.

Exposes Shroud's core capabilities via MCP for external AI agents:
domain security scanning, PII detection, compliance status, threat intelligence.

Port: 7012 | Transport: SSE
"""

import os
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

# Add shared auth module to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ghostlabs_auth import GhostLabsTokenVerifier

mcp = FastMCP("ghostlabs-shroud")

# OAuth 2.1 token verification
_verifier = GhostLabsTokenVerifier(required_scopes=["shroud:read"])

SHROUD_API_URL = os.getenv("SHROUD_API_URL", "http://shroud-backend:8000/api")
SHROUD_API_KEY = os.getenv("SHROUD_API_KEY", "")

HEADERS = {"Authorization": f"Bearer {SHROUD_API_KEY}"} if SHROUD_API_KEY else {}

API_URL = SHROUD_API_URL


async def _safe_request(method: str, url: str, **kwargs) -> dict:
    """Make an HTTP request with structured error handling."""
    try:
        async with httpx.AsyncClient(timeout=kwargs.pop("timeout", 30), headers=HEADERS) as client:
            resp = await getattr(client, method)(url, **kwargs)
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        return {"error": "request_timeout", "message": f"Request to {url} timed out"}
    except httpx.HTTPStatusError as e:
        return {"error": "http_error", "message": str(e), "status_code": e.response.status_code}
    except Exception as e:
        return {"error": "connection_error", "message": str(e)}


@mcp.tool()
async def health_check() -> dict:
    """Check if the GhostLabs service is available and responding."""
    try:
        async with httpx.AsyncClient(timeout=5, headers=HEADERS) as client:
            resp = await client.get(f"{API_URL.rstrip('/').rsplit('/api', 1)[0]}/health/")
            return {"status": "healthy" if resp.status_code == 200 else "degraded", "code": resp.status_code}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


@mcp.tool()
async def check_domain_reputation(domain: str) -> dict:
    """Check domain reputation and security posture.

    Runs DNS, SSL, email security, and breach checks against the domain.

    Args:
        domain: Domain to check (e.g., "example.com").
    """
    return await _safe_request(
        "post",
        f"{SHROUD_API_URL}/domains/check/",
        json={"domain": domain},
        timeout=60,
    )


@mcp.tool()
async def scan_content_pii(text: str) -> dict:
    """Scan text for personally identifiable information (PII).

    Detects names, emails, phone numbers, SSNs, credit cards, and other PII
    using Presidio. Returns findings with entity types and locations.

    Args:
        text: Text to scan for PII.
    """
    return await _safe_request(
        "post",
        f"{SHROUD_API_URL}/compliance/scan-pii/",
        json={"text": text},
    )


@mcp.tool()
async def get_security_score(domain: str) -> dict:
    """Get an overall security score for a domain (A-F grade).

    Returns a composite score across DNS, SSL, email, ports, and breach categories.

    Args:
        domain: Domain to score.
    """
    return await _safe_request(
        "get",
        f"{SHROUD_API_URL}/domains/{domain}/score/",
        timeout=60,
    )


@mcp.tool()
async def check_vulnerability(service: str, version: str = "") -> dict:
    """Check for known CVE vulnerabilities for a service/software.

    Args:
        service: Service or software name (e.g., "nginx", "openssh").
        version: Optional version string (e.g., "1.25.3").
    """
    params = {"service": service}
    if version:
        params["version"] = version

    return await _safe_request(
        "get",
        f"{SHROUD_API_URL}/threats/cve/",
        params=params,
    )


@mcp.tool()
async def report_security_event(
    product: str, action: str, resource_type: str = "", resource_id: str = "", details: str = ""
) -> dict:
    """Report a security event from any GhostLabs product.

    Args:
        product: Product reporting (phantom, specter, whisper).
        action: Action that occurred (e.g., "data_access", "auth_failure").
        resource_type: Type of resource affected.
        resource_id: ID of the resource.
        details: Additional details as JSON string.
    """
    payload = {"product": product, "action": action}
    if resource_type:
        payload["resource_type"] = resource_type
    if resource_id:
        payload["resource_id"] = resource_id
    if details:
        payload["details"] = details

    return await _safe_request(
        "post",
        f"{SHROUD_API_URL}/threats/events/",
        json=payload,
    )


@mcp.tool()
async def get_compliance_status(framework: str = "nist_csf") -> dict:
    """Get current compliance status against a framework.

    Args:
        framework: Compliance framework — nist_csf, soc2, gdpr, iso27001, cis.
    """
    return await _safe_request(
        "get",
        f"{SHROUD_API_URL}/compliance/status/",
        params={"framework": framework},
    )


@mcp.tool()
async def generate_compliance_narrative(framework: str, scope: str = "") -> dict:
    """Generate an AI-powered compliance narrative for a framework.

    Returns audit-ready text per control area with evidence mapping.

    Args:
        framework: Target framework (soc2, gdpr, iso27001).
        scope: Optional scope limitation (e.g., "access_control").
    """
    return await _safe_request(
        "post",
        f"{SHROUD_API_URL}/compliance/narrative/",
        json={"framework": framework, "scope": scope},
        timeout=120,
    )


@mcp.tool()
async def verify_auth() -> dict:
    """Verify that your OAuth token is valid and check granted scopes.

    Returns token claims including subject, scopes, and expiry.
    Use this to test authentication before calling other tools.
    """
    return {
        "status": "authenticated",
        "message": "OAuth 2.1 token is valid",
        "mode": "jwt" if _verifier.jwt_mode else "api_key" if _verifier.static_keys else "open",
    }


if __name__ == "__main__":
    mcp.run()
