# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Tests for AlignmentLLMClient."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestAlignmentDropParams:
    """Regression: AlignmentLLMClient._make_llm_request must pass drop_params=True."""

    @pytest.mark.asyncio
    async def test_acompletion_called_with_drop_params(self):
        """AlignmentLLMClient must pass drop_params=True to acompletion."""
        from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )

        client = AlignmentLLMClient(
            model="gpt-5.4-2026-03-05",
            api_key="test-key",
        )

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"alignment": "verified"}'

        with patch(
            "skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client.acompletion",
            new_callable=AsyncMock,
        ) as mock_acompletion:
            mock_acompletion.return_value = mock_response
            await client._make_llm_request("test prompt")

        assert mock_acompletion.called, "acompletion should have been called"
        call_kwargs = mock_acompletion.call_args
        kwargs = call_kwargs.kwargs if call_kwargs.kwargs else call_kwargs[1]
        assert kwargs.get("drop_params") is True, f"acompletion must be called with drop_params=True, got: {kwargs}"

    @pytest.mark.asyncio
    async def test_openai_user_param_sent_for_openai_model(self):
        """AlignmentLLMClient sends the optional user field for OpenAI-like routes."""
        from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )

        raw_user = '{"appkey":"test-appkey"}'
        client = AlignmentLLMClient(
            model="gpt-5-nano",
            api_key="test-key",
            llm_user=raw_user,
        )

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"alignment": "verified"}'

        with patch(
            "skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client.acompletion",
            new_callable=AsyncMock,
        ) as mock_acompletion:
            mock_acompletion.return_value = mock_response
            await client._make_llm_request("test prompt")

        kwargs = mock_acompletion.call_args.kwargs
        assert kwargs["user"] == raw_user
        assert kwargs.get("drop_params") is True

    @pytest.mark.asyncio
    async def test_openai_user_param_not_sent_for_non_openai_model(self):
        """AlignmentLLMClient does not send the optional user field for non-OpenAI routes."""
        from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import (
            AlignmentLLMClient,
        )

        client = AlignmentLLMClient(
            model="gemini/gemini-2.0-flash",
            api_key="test-key",
            llm_user='{"appkey":"test-appkey"}',
        )

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"alignment": "verified"}'

        with patch(
            "skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client.acompletion",
            new_callable=AsyncMock,
        ) as mock_acompletion:
            mock_acompletion.return_value = mock_response
            await client._make_llm_request("test prompt")

        kwargs = mock_acompletion.call_args.kwargs
        assert "user" not in kwargs
        assert kwargs.get("drop_params") is True
