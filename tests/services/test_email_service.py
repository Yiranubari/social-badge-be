from unittest.mock import MagicMock, patch

import pytest
import resend

from app.core.exceptions import EmailDeliveryError
from app.services.email_service import send_verification_email


@patch("app.services.email_service.resend.Emails.send")
async def test_sends_email_with_correct_params(mock_send: MagicMock) -> None:
    mock_send.return_value = {"id": "test-id"}

    await send_verification_email("user@example.com", "test-token")

    mock_send.assert_called_once()
    call_args = mock_send.call_args[0][0]
    assert call_args["to"] == ["user@example.com"]
    assert "test-token" in call_args["html"]
    assert call_args["subject"] == "Verify your Social Badge account"


@patch("app.services.email_service.resend.Emails.send")
async def test_raises_email_delivery_error_on_failure(
    mock_send: MagicMock,
) -> None:
    mock_send.side_effect = resend.exceptions.ResendError(
        "API error", "error_type", "400", "suggested action"
    )

    with pytest.raises(EmailDeliveryError):
        await send_verification_email("user@example.com", "test-token")
