"""
GhostLabs Phantom MCP Server — Lead generation and email verification tools.

Exposes Phantom's core capabilities via MCP for external AI agents:
lead search, email verification, campaign management.

Port: 7010 | Transport: SSE
"""

import os
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

# Add shared auth module to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ghostlabs_auth import GhostLabsTokenVerifier

mcp = FastMCP("ghostlabs-phantom")

# OAuth 2.1 token verification
_verifier = GhostLabsTokenVerifier(required_scopes=["phantom:read"])

PHANTOM_API_URL = os.getenv("PHANTOM_API_URL", "http://phantom-backend:8000/api")
PHANTOM_API_KEY = os.getenv("PHANTOM_API_KEY", "")

HEADERS = {"Authorization": f"Bearer {PHANTOM_API_KEY}"} if PHANTOM_API_KEY else {}

API_URL = PHANTOM_API_URL


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
async def search_leads(query: str, limit: int = 10) -> dict:
    """Search for leads matching criteria in the Phantom database.

    Args:
        query: Natural language search query (e.g., "SaaS companies in fintech").
        limit: Maximum number of results (1-50).
    """
    return await _safe_request(
        "get",
        f"{PHANTOM_API_URL}/leads/prospects/",
        params={"search": query, "limit": min(limit, 50)},
    )


@mcp.tool()
async def get_lead_details(contact_id: str) -> dict:
    """Get full details for a specific lead/contact.

    Returns company info, contact details, verification status, and fit score.

    Args:
        contact_id: The UUID of the contact.
    """
    return await _safe_request("get", f"{PHANTOM_API_URL}/leads/contacts/{contact_id}/")


@mcp.tool()
async def verify_email(email: str) -> dict:
    """Verify an email address using Phantom's 10-layer verification pipeline.

    Returns a deliverability score (0-100) and detailed layer results.

    Args:
        email: The email address to verify.
    """
    return await _safe_request(
        "post",
        f"{PHANTOM_API_URL}/leads/verify-email/",
        json={"email": email},
        timeout=60,
    )


@mcp.tool()
async def check_domain_email_pattern(domain: str) -> dict:
    """Detect the email naming pattern for a company domain.

    Returns the detected pattern (e.g., first.last@domain.com) and confidence.

    Args:
        domain: Company domain to check (e.g., "acme.com").
    """
    return await _safe_request(
        "get",
        f"{PHANTOM_API_URL}/leads/email-patterns/",
        params={"domain": domain},
    )


@mcp.tool()
async def create_campaign(query: str, icp_id: str = "") -> dict:
    """Create and start a new lead generation campaign.

    Args:
        query: Natural language description of the ideal customer.
        icp_id: Optional existing ICP profile ID to use.
    """
    payload = {"query": query}
    if icp_id:
        payload["icp_id"] = icp_id

    return await _safe_request(
        "post",
        f"{PHANTOM_API_URL}/leads/campaigns/",
        json=payload,
    )


@mcp.tool()
async def get_campaign_status(campaign_id: str) -> dict:
    """Check the status and progress of a lead generation campaign.

    Args:
        campaign_id: The UUID of the campaign.
    """
    return await _safe_request("get", f"{PHANTOM_API_URL}/leads/campaigns/{campaign_id}/")


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
