from unittest.mock import MagicMock

from iam_auditor import check_mfa


def test_check_mfa_flags_user_without_device():
    fake_client = MagicMock()
    fake_client.list_mfa_devices.return_value = {"MFADevices": []}

    assert check_mfa(fake_client, "alice") is True


def test_check_mfa_passes_user_with_device():
    fake_client = MagicMock()
    fake_client.list_mfa_devices.return_value = {
        "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/alice"}]
    }

    assert check_mfa(fake_client, "alice") is False
