"""Tests for GhostLabs OAuth 2.1 authentication."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
import asyncio

# Ensure ghostlabs_auth is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestGhostLabsTokenVerifier(unittest.TestCase):

    def _run(self, coro):
        return asyncio.run(coro)

    def test_static_key_accepted(self):
        with patch.dict(os.environ, {"MCP_API_KEYS": "test-key-1,test-key-2", "OAUTH_JWKS_URL": ""}):
            from ghostlabs_auth.token_verifier import GhostLabsTokenVerifier
            verifier = GhostLabsTokenVerifier()
            result = self._run(verifier.verify_token("test-key-1"))
            self.assertIsNotNone(result)
            self.assertEqual(result["sub"], "api-key")

    def test_static_key_rejected(self):
        with patch.dict(os.environ, {"MCP_API_KEYS": "test-key-1", "OAUTH_JWKS_URL": ""}):
            from ghostlabs_auth.token_verifier import GhostLabsTokenVerifier
            verifier = GhostLabsTokenVerifier()
            result = self._run(verifier.verify_token("wrong-key"))
            self.assertIsNone(result)

    def test_empty_token_rejected(self):
        with patch.dict(os.environ, {"MCP_API_KEYS": "test-key", "OAUTH_JWKS_URL": ""}):
            from ghostlabs_auth.token_verifier import GhostLabsTokenVerifier
            verifier = GhostLabsTokenVerifier()
            result = self._run(verifier.verify_token(""))
            self.assertIsNone(result)

    def test_no_auth_configured_warning(self):
        with patch.dict(os.environ, {"MCP_API_KEYS": "", "OAUTH_JWKS_URL": ""}, clear=False):
            from ghostlabs_auth.token_verifier import GhostLabsTokenVerifier
            verifier = GhostLabsTokenVerifier()
            self.assertFalse(verifier.jwt_mode)
            self.assertEqual(verifier.static_keys, [])

    def test_jwt_mode_enabled_with_jwks_url(self):
        with patch.dict(os.environ, {"OAUTH_JWKS_URL": "https://example.com/.well-known/jwks.json"}):
            from ghostlabs_auth.token_verifier import GhostLabsTokenVerifier
            verifier = GhostLabsTokenVerifier()
            self.assertTrue(verifier.jwt_mode)

    def test_required_scopes_stored(self):
        with patch.dict(os.environ, {"MCP_API_KEYS": "key", "OAUTH_JWKS_URL": ""}):
            from ghostlabs_auth.token_verifier import GhostLabsTokenVerifier
            verifier = GhostLabsTokenVerifier(required_scopes=["phantom:read"])
            self.assertEqual(verifier.required_scopes, ["phantom:read"])


if __name__ == "__main__":
    unittest.main()
