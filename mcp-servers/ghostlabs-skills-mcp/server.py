"""
GhostLabs Skills MCP Server — Skill discovery and loading for any MCP client.

Exposes the shared Skills Engine via MCP protocol, allowing external AI agents
to find, load, and use GhostLabs skills.

Port: 7014 | Transport: SSE
"""

import os
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

# Add shared auth module to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ghostlabs_auth import GhostLabsTokenVerifier

mcp = FastMCP("ghostlabs-skills")

# OAuth 2.1 token verification
_verifier = GhostLabsTokenVerifier(required_scopes=["skills:read"])

SKILLS_API_URL = os.getenv("SKILLS_API_URL", "http://ghostlabs-backend:8000/api")

HEADERS = {}

API_URL = SKILLS_API_URL


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
async def find_skills(query: str, product: str = "", max_results: int = 3) -> dict:
    """Search for skills relevant to a query using semantic similarity.

    Returns matching skills with name, description, and similarity score.
    Use get_skill to load full instructions for a match.

    Args:
        query: Natural language description of what expertise you need.
        product: Filter by product (specter, whisper, shroud, phantom). Empty for all.
        max_results: Maximum number of results (1-10).
    """
    return await _safe_request(
        "post",
        f"{SKILLS_API_URL}/skills/test_match/",
        json={"query": query, "product": product or "shared", "max_results": max_results},
    )


@mcp.tool()
async def get_skill(skill_id: str) -> dict:
    """Load full instructions for a skill by ID.

    Returns the complete SKILL.md markdown body with methodology,
    frameworks, and detailed guidance.

    Args:
        skill_id: The UUID of the skill (from find_skills results).
    """
    data = await _safe_request("get", f"{SKILLS_API_URL}/skills/{skill_id}/")
    if "error" in data:
        return data
    return {
        "name": data["name"],
        "product": data["product"],
        "description": data["description"],
        "instructions": data["instructions"],
        "allowed_tools": data["allowed_tools"],
    }


@mcp.tool()
async def get_skill_resources(skill_id: str) -> list:
    """List available resources (scripts, references, templates) for a skill.

    Args:
        skill_id: The UUID of the skill.
    """
    return await _safe_request("get", f"{SKILLS_API_URL}/skills/{skill_id}/resources/")


@mcp.tool()
async def list_skills(product: str = "", source: str = "") -> list:
    """List all available skills, optionally filtered by product or source.

    Args:
        product: Filter by product (specter, whisper, shroud, phantom). Empty for all.
        source: Filter by source (builtin, customer, community). Empty for all.
    """
    params = {}
    if product:
        params["product"] = product
    if source:
        params["source"] = source

    return await _safe_request("get", f"{SKILLS_API_URL}/skills/", params=params)


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
