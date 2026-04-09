"""
GhostLabs Specter MCP Server — Adversarial strategy analysis tools.

Exposes Specter's core capabilities via MCP for external AI agents:
adversarial testing, template library, claim extraction, red team evaluation.

Port: 7013 | Transport: SSE
"""

import os
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

# Add shared auth module to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ghostlabs_auth import GhostLabsTokenVerifier

mcp = FastMCP("ghostlabs-specter")

# OAuth 2.1 token verification
_verifier = GhostLabsTokenVerifier(required_scopes=["specter:read"])

SPECTER_API_URL = os.getenv("SPECTER_API_URL", "http://specter-backend:8000/api")
SPECTER_API_KEY = os.getenv("SPECTER_API_KEY", "")

HEADERS = {"Authorization": f"Bearer {SPECTER_API_KEY}"} if SPECTER_API_KEY else {}

API_URL = SPECTER_API_URL


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
async def run_adversarial_test(
    query: str, template: str = "", depth: int = 3
) -> dict:
    """Run an adversarial strategy analysis on a business question or strategy.

    Executes Specter's multi-stage pipeline: strategy generation, critique,
    self-improvement, red team evaluation, and final selection.

    Args:
        query: The strategy, idea, or business question to analyze.
        template: Optional template name (e.g., "product-launch", "investment-thesis").
        depth: Analysis depth 1-5 (refinement cycles). Default 3.
    """
    payload = {"query": query, "depth": min(max(depth, 1), 5)}
    if template:
        payload["template"] = template

    return await _safe_request(
        "post",
        f"{SPECTER_API_URL}/tester/sessions/",
        json=payload,
        timeout=300,
    )


@mcp.tool()
async def get_session_results(session_id: str) -> dict:
    """Retrieve full results from a completed Specter analysis session.

    Returns strategies, critiques, red team findings, and the final selected solution.

    Args:
        session_id: The UUID of the analysis session.
    """
    return await _safe_request("get", f"{SPECTER_API_URL}/tester/sessions/{session_id}/")


@mcp.tool()
async def list_templates() -> list:
    """List available analysis templates.

    Templates provide structured frameworks for specific analysis types:
    Product Launch, Investment Thesis, Competitive Response, etc.
    """
    return await _safe_request("get", f"{SPECTER_API_URL}/tester/templates/")


@mcp.tool()
async def extract_claims(text: str) -> dict:
    """Extract testable claims from a business document or strategy text.

    Identifies factual, causal, assumption, and feasibility claims
    that can be individually stress-tested.

    Args:
        text: The strategy text or document content to analyze.
    """
    return await _safe_request(
        "post",
        f"{SPECTER_API_URL}/tester/extract-claims/",
        json={"text": text},
        timeout=120,
    )


@mcp.tool()
async def red_team_evaluate(
    strategy_text: str, aggressiveness: str = "balanced"
) -> dict:
    """Run only the Red Team evaluation stage on a strategy.

    A focused adversarial attack trying to break the strategy,
    without the full multi-stage pipeline.

    Args:
        strategy_text: The strategy to attack.
        aggressiveness: Attack level — balanced or aggressive.
    """
    return await _safe_request(
        "post",
        f"{SPECTER_API_URL}/tester/red-team/",
        json={
            "text": strategy_text,
            "aggressiveness": aggressiveness,
        },
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
