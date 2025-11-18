"""Test test mode functionality."""

import pytest

import jaraco.abode
from jaraco.abode.helpers import urls

from .mock import cms as CMS
from .mock import login as LOGIN
from .mock import oauth_claims as OAUTH_CLAIMS


class TestTestMode:
    """Test the test mode functionality."""

    def test_get_test_mode_disabled(self, m):
        """Test getting test mode status when disabled."""
        m.post(urls.LOGIN, json=LOGIN.post_response_ok())
        m.get(urls.OAUTH_TOKEN, json=OAUTH_CLAIMS.get_response_ok())
        m.get(urls.SECURITY_PANEL, json=CMS.get_security_panel_response(test_mode_active=False))

        self.client.login()
        test_mode = self.client.get_test_mode()

        assert test_mode is False

    def test_get_test_mode_enabled(self, m):
        """Test getting test mode status when enabled."""
        m.post(urls.LOGIN, json=LOGIN.post_response_ok())
        m.get(urls.OAUTH_TOKEN, json=OAUTH_CLAIMS.get_response_ok())
        m.get(urls.SECURITY_PANEL, json=CMS.get_security_panel_response(test_mode_active=True))

        self.client.login()
        test_mode = self.client.get_test_mode()

        assert test_mode is True

    def test_set_test_mode_enable(self, m):
        """Test enabling test mode."""
        m.post(urls.LOGIN, json=LOGIN.post_response_ok())
        m.get(urls.OAUTH_TOKEN, json=OAUTH_CLAIMS.get_response_ok())
        m.post(urls.CMS_SETTINGS, json=CMS.post_cms_settings_response(test_mode_active=True))

        self.client.login()
        result = self.client.set_test_mode(True)

        assert result['testModeActive'] is True
        assert result['monitoringActive'] is True

    def test_set_test_mode_disable(self, m):
        """Test disabling test mode."""
        m.post(urls.LOGIN, json=LOGIN.post_response_ok())
        m.get(urls.OAUTH_TOKEN, json=OAUTH_CLAIMS.get_response_ok())
        m.post(urls.CMS_SETTINGS, json=CMS.post_cms_settings_response(test_mode_active=False))

        self.client.login()
        result = self.client.set_test_mode(False)

        assert result['testModeActive'] is False

    def test_set_test_mode_invalid_type(self, m):
        """Test that set_test_mode raises exception for non-boolean values."""
        m.post(urls.LOGIN, json=LOGIN.post_response_ok())
        m.get(urls.OAUTH_TOKEN, json=OAUTH_CLAIMS.get_response_ok())

        self.client.login()

        with pytest.raises(jaraco.abode.Exception) as exc_info:
            self.client.set_test_mode("true")
        assert exc_info.value.message == "Test mode must be a boolean value"

        with pytest.raises(jaraco.abode.Exception) as exc_info:
            self.client.set_test_mode(1)
        assert exc_info.value.message == "Test mode must be a boolean value"
