# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Shared pytest fixtures and mock helpers for aura-inspector unit tests.

All scanners receive a mock AuraHelper rather than making real HTTP requests.
The mock hierarchy:
  MockActionResponse  – mimics AuraActionResponse (.is_success(), .return_value, .error_message)
  MockBulkResponse    – mimics the object returned by AuraHelper.send_aura_bulk()
  make_aura()         – factory that returns a configured MagicMock AuraHelper
"""

import os
import sys

import pytest

# ── ensure src/ is importable regardless of CWD ─────────────────────────────
# Append src/ AFTER site-packages so the official `mcp` SDK (used by fastmcp)
# is found before our src/mcp/ package, avoiding a naming conflict.
_SRC = os.path.join(os.path.dirname(__file__), '..', 'src')
_SRC_ABS = os.path.abspath(_SRC)
if _SRC_ABS not in sys.path:
    sys.path.append(_SRC_ABS)


# ════════════════════════════════════════════════════════════════════════════
# Mock primitives
# ════════════════════════════════════════════════════════════════════════════

class MockActionResponse:
    """Minimal stand-in for AuraActionResponse."""

    def __init__(
        self,
        success: bool = True,
        return_value=None,
        error_message: str | None = None,
    ):
        self._success = success
        self.return_value = return_value
        self.error_message = error_message

    def is_success(self) -> bool:
        return self._success


class MockBulkResponse:
    """Minimal stand-in for the aggregate response of AuraHelper.send_aura_bulk()."""

    def __init__(self, responses: list[MockActionResponse] | None = None):
        self.actions_responses = responses or []


# ════════════════════════════════════════════════════════════════════════════
# AuraHelper factory
# ════════════════════════════════════════════════════════════════════════════

def make_aura(
    objects: list[str] | None = None,
    bulk_response: MockBulkResponse | None = None,
    home_urls: dict | None = None,
    custom_controllers: list[str] | None = None,
):
    """
    Return a MagicMock configured as an AuraHelper.

    Parameters
    ----------
    objects            : Return value of aura.get_objects().
    bulk_response      : Return value of aura.send_aura_bulk().
                         Defaults to an empty MockBulkResponse.
    home_urls          : Return value of aura.get_object_home_urls().
    custom_controllers : Return value of aura.get_custom_controllers().
    """
    from unittest.mock import MagicMock

    aura = MagicMock()
    aura.get_objects.return_value = objects if objects is not None else []
    aura.send_aura_bulk.return_value = bulk_response or MockBulkResponse()
    aura.get_object_home_urls.return_value = home_urls if home_urls is not None else {}
    aura.get_custom_controllers.return_value = custom_controllers if custom_controllers is not None else []
    return aura


# ════════════════════════════════════════════════════════════════════════════
# Pytest fixtures
# ════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def empty_aura():
    """AuraHelper that returns nothing from any method."""
    return make_aura()


@pytest.fixture
def aura_with_sensitive_objects():
    """AuraHelper whose object list contains standard sensitive SF objects."""
    return make_aura(objects=['User', 'Profile', 'Organization', 'Account', 'Product2'])


@pytest.fixture
def aura_with_safe_objects():
    """AuraHelper whose object list contains only non-sensitive objects."""
    return make_aura(objects=['Product2', 'PricebookEntry', 'KnowledgeArticle'])


@pytest.fixture
def aura_with_list_view_records():
    """AuraHelper where send_aura_bulk returns Account records for ListViewDataProviderController."""
    resp = MockActionResponse(
        success=True,
        return_value={
            'records': {
                'records': [
                    {'Id': '001000000000001', 'Name': 'ACME Corp'},
                    {'Id': '001000000000002', 'Name': 'Globex'},
                ],
            },
        },
    )
    return make_aura(
        objects=['Account'],
        bulk_response=MockBulkResponse([resp]),
    )
