"""
GhostLabs Whisper MCP Server — Business intelligence and data query tools.

Exposes Whisper's core capabilities via MCP for external AI agents:
natural language to SQL, document search, report generation.

Port: 7011 | Transport: SSE
"""

import os
import sys
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

# Add shared auth module to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ghostlabs_auth import GhostLabsTokenVerifier

mcp = FastMCP("ghostlabs-whisper")

# OAuth 2.1 token verification
_verifier = GhostLabsTokenVerifier(required_scopes=["whisper:read"])

WHISPER_API_URL = os.getenv("WHISPER_API_URL", "http://whisper-backend:8000/api")
WHISPER_API_KEY = os.getenv("WHISPER_API_KEY", "")

HEADERS = {"Authorization": f"Bearer {WHISPER_API_KEY}"} if WHISPER_API_KEY else {}

API_URL = WHISPER_API_URL


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
async def query_business_data(question: str, company_id: str = "") -> dict:
    """Ask a business question in natural language and get data-driven answers.

    Whisper translates your question to SQL, queries the database, and returns
    formatted results with analysis.

    Args:
        question: Natural language question (e.g., "What were total sales last month?").
        company_id: Optional company ID for multi-tenant queries.
    """
    payload = {"message": question}
    if company_id:
        payload["company_id"] = company_id

    return await _safe_request(
        "post",
        f"{WHISPER_API_URL}/chat/query/",
        json=payload,
        timeout=120,
    )


@mcp.tool()
async def search_documents(query: str, file_types: str = "") -> dict:
    """Search company documents (SharePoint, uploaded files) for relevant content.

    Args:
        query: Search query.
        file_types: Optional comma-separated file type filter (e.g., "pdf,docx").
    """
    params = {"q": query}
    if file_types:
        params["file_types"] = file_types

    return await _safe_request(
        "get",
        f"{WHISPER_API_URL}/documents/search/",
        params=params,
        timeout=60,
    )


@mcp.tool()
async def get_conversation_history(conversation_id: str, limit: int = 20) -> dict:
    """Retrieve past conversation messages for context.

    Args:
        conversation_id: The UUID of the conversation.
        limit: Maximum number of messages to return.
    """
    return await _safe_request(
        "get",
        f"{WHISPER_API_URL}/chat/conversations/{conversation_id}/messages/",
        params={"limit": limit},
    )


@mcp.tool()
async def generate_report(prompt: str, output_format: str = "markdown") -> dict:
    """Generate a formatted business report from a natural language prompt.

    Args:
        prompt: Description of the report to generate (e.g., "Monthly sales summary").
        output_format: Output format — markdown, json, pdf, or xlsx.
    """
    return await _safe_request(
        "post",
        f"{WHISPER_API_URL}/reports/generate/",
        json={"prompt": prompt, "format": output_format},
        timeout=120,
    )


@mcp.tool()
async def create_chart(data_query: str, chart_type: str = "auto") -> dict:
    """Generate a chart specification from a data query.

    Returns a Recharts-compatible JSON spec that can be rendered in a frontend.

    Args:
        data_query: Natural language description of the data to visualize.
        chart_type: Chart type — auto, line, bar, pie, area, scatter, or table.
    """
    return await _safe_request(
        "post",
        f"{WHISPER_API_URL}/visualizations/create/",
        json={"query": data_query, "chart_type": chart_type},
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
