# Getting Started with GhostLabs AI

## Prerequisites

- An AI coding agent that supports SKILL.md (Claude Code, Codex, Cursor, Gemini CLI)
- For MCP servers: Python 3.12+ and a GhostLabs account

## Installing Skills

### Option 1: Claude Code Plugin

```bash
claude skills add ghostlabs-ai/ghostlabs-ai
```

This installs all 16 skills. They auto-trigger when your conversation matches their domain.

### Option 2: Manual Installation

Clone the repo and point your agent to the skills directory:

```bash
git clone https://github.com/ghostlabs-ai/ghostlabs-ai.git
```

## Using Skills

Skills activate automatically. Examples:

- Ask about "building an ICP" → `icp-builder` triggers
- Ask about "security analysis" → `security-threat-analyst` triggers
- Ask about "testing a strategy" → `adversarial-strategy-test` triggers
- Ask about "SQL optimization" → `sql-optimization-patterns` triggers

## Setting Up MCP Servers

### 1. Install dependencies

```bash
cd mcp-servers/ghostlabs-shroud-mcp
pip install mcp httpx
```

### 2. Configure environment

```bash
export SHROUD_API_URL=https://shroud.ghostlabs.ai/api
export SHROUD_API_KEY=your-api-key
```

### 3. Run the server

```bash
python server.py
```

### 4. Connect to your MCP client

Add the server to your MCP configuration file. Each client has its own format — check your client's documentation.

## Available MCP Tools

### Phantom (Lead Generation)
- `search_leads` — Search for leads matching criteria
- `get_lead_details` — Full contact and company info
- `verify_email` — 10-layer email verification
- `check_domain_email_pattern` — Detect email naming patterns
- `create_campaign` — Start a lead generation campaign
- `get_campaign_status` — Check campaign progress

### Whisper (Business Intelligence)
- `query_business_data` — Natural language to SQL with analysis
- `search_documents` — Search company documents
- `get_conversation_history` — Retrieve past conversations
- `generate_report` — Create formatted business reports
- `create_chart` — Generate chart specifications from data

### Specter (Strategy Testing)
- `run_adversarial_test` — Full multi-stage adversarial analysis
- `get_session_results` — Retrieve completed analysis
- `list_templates` — Browse analysis templates
- `extract_claims` — Identify testable claims from text
- `red_team_evaluate` — Focused adversarial attack on a strategy

### Shroud (Security & Compliance)
- `check_domain_reputation` — DNS, SSL, email security checks
- `scan_content_pii` — PII detection (14 entity types)
- `get_security_score` — Composite A-F domain grade
- `check_vulnerability` — CVE lookup by service/version
- `report_security_event` — Report security events
- `get_compliance_status` — Framework compliance status
- `generate_compliance_narrative` — AI-powered audit text

### Skills (Cross-Product)
- `find_skills` — Semantic skill search
- `get_skill` — Load full skill instructions
- `get_skill_resources` — List skill resources
- `list_skills` — Browse all available skills
