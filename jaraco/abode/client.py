"""
An Abode alarm Python library.
"""

import functools
import logging
import uuid

from more_itertools import consume
from requests.exceptions import RequestException
from requests_toolbelt import sessions

import jaraco
from jaraco.collections import Everything
from jaraco.functools import retry
from jaraco.itertools import always_iterable
from jaraco.net.http import cookies

from . import config, settings
from .automation import Automation
from .devices import alarm as ALARM
from .devices.base import Device, Unknown
from .event_controller import EventController
from .exceptions import AuthenticationException
from .helpers import errors as ERROR
from .helpers import urls

log = logging.getLogger(__name__)


@retry(
    retries=1,
    cleanup=lambda: config.paths.user_data.joinpath('cookies.json').unlink(),
    trap=Exception,
)
def _cookies():
    return cookies.ShelvedCookieJar.create(config.paths.user_data)


class Client:
    """Client to an Abode system."""

    def __init__(
        self,
        username=None,
        password=None,
        auto_login=False,
        get_devices=False,
        get_automations=False,
    ):
        self._session = None
        self._token = None
        self._panel = None
        self._user = None
        self._username = username
        self._password = password

        self._event_controller = EventController(self)

        self._default_alarm_mode = 'away'

        self._devices = None

        self._automations = None

        self._session = sessions.BaseUrlSession(urls.BASE)
        self._session.cookies = _cookies()

        if auto_login:
            self.login()

        if get_devices:
            self.get_devices()

        if get_automations:
            self.get_automations()

    def login(self, username=None, password=None, mfa_code=None):
        """Explicit Abode login."""

        self._token = None

        username = username or self._username
        password = password or self._password

        if not isinstance(username, str):
            raise AuthenticationException(ERROR.USERNAME)

        if not isinstance(password, str):
            raise AuthenticationException(ERROR.PASSWORD)

        login_data = {
            'id': username,
            'password': password,
            'uuid': self._session.cookies.get('uuid') or str(uuid.uuid1()),
        }

        if mfa_code is not None:
            login_data['mfa_code'] = mfa_code
            login_data['remember_me'] = 1

        response = self._session.post(urls.LOGIN, json=login_data)
        AuthenticationException.raise_for(response)
        response_object = response.json()

        # Check for multi-factor authentication
        if 'mfa_type' in response_object:
            if response_object['mfa_type'] == "google_authenticator":
                raise AuthenticationException(ERROR.MFA_CODE_REQUIRED)

            raise AuthenticationException(ERROR.UNKNOWN_MFA_TYPE)

        oauth_response = self._session.get(urls.OAUTH_TOKEN)
        AuthenticationException.raise_for(oauth_response)
        oauth_response_object = oauth_response.json()

        log.debug("Login URL: %s", urls.LOGIN)
        log.debug("Login Response: %s", response.text)

        self._token = response_object['token']
        self._panel = response_object['panel']
        self._user = response_object['user']
        self._oauth_token = oauth_response_object['access_token']

        log.info("Login successful")

    def logout(self):
        """Explicit Abode logout."""
        if not self._token:
            return

        header_data = {'ABODE-API-KEY': self._token}

        self._session = sessions.BaseUrlSession(urls.BASE)
        self._token = None
        self._panel = None
        self._user = None
        self._devices = None
        self._automations = None

        try:
            response = self._session.post(urls.LOGOUT, headers=header_data)
        except OSError as exc:
            log.warning("Caught exception during logout: %s", exc)
            return

        AuthenticationException.raise_for(response)

        log.debug("Logout URL: %s", urls.LOGOUT)
        log.debug("Logout Response: %s", response.text)

        log.info("Logout successful")

    def refresh(self):
        """Do a full refresh of all devices and automations."""
        self.get_devices(refresh=True)
        self.get_automations(refresh=True)

    def get_devices(self, refresh=False, generic_type=None):
        """Get all devices from Abode."""
        if refresh or self._devices is None:
            self._load_devices()

        spec_types = (
            Everything() if generic_type is None else set(always_iterable(generic_type))
        )

        return [
            device
            for device in self._devices.values()
            if device.generic_type in spec_types
        ]

    def _load_devices(self):
        if self._devices is None:
            self._devices = {}

        log.info("Updating all devices...")
        response = self.send_request("get", urls.DEVICES)
        devices = always_iterable(response.json())

        log.debug("Get Devices URL (get): %s", urls.AUTOMATION)
        log.debug("Get Devices Response: %s", response.text)

        consume(map(self._load_device, devices))

        # We will be treating the Abode panel itself as an armable device.
        panel_response = self.send_request("get", urls.PANEL)
        panel_json = panel_response.json()

        self._panel.update(panel_json)

        log.debug("Get Mode Panel URL (get): %s", urls.AUTOMATION)
        log.debug("Get Mode Panel Response: %s", response.text)

        alarm_device = self._devices.get(ALARM.id(1))

        if alarm_device:
            alarm_device.update(self._panel)
        else:
            alarm_device = ALARM.create_alarm(self._panel, self)
            self._devices[alarm_device.id] = alarm_device

    def _load_device(self, doc):
        self._reuse_device(doc) or self._create_new_device(doc)

    def _reuse_device(self, doc):
        device = self._devices.get(doc['id'])

        if not device:
            return

        device.update(doc)
        return device

    def _create_new_device(self, doc):
        device = Device.new(doc, self)

        if isinstance(device, Unknown):
            log.debug("Skipping unknown device: %s", doc)
            return

        self._devices[device.id] = device

    def get_device(self, device_id, refresh=False):
        """Get a single device."""
        if self._devices is None:
            self.get_devices()
            refresh = False

        device = self._devices.get(device_id)

        if device and refresh:
            device.refresh()

        return device

    def get_automations(self, refresh=False):
        """Get all automations."""
        if refresh or self._automations is None:
            self._update_all()

        return list(self._automations.values())

    def _update_all(self):
        if self._automations is None:
            # Set up the device libraries
            self._automations = {}

        log.info("Updating all automations...")
        resp = self.send_request("get", urls.AUTOMATION)
        log.debug("Get Automations URL (get): %s", urls.AUTOMATION)
        log.debug("Get Automations Response: %s", resp.text)

        for state in always_iterable(resp.json()):
            # Attempt to reuse an existing automation object
            automation = self._automations.get(str(state['id']))

            # No existing automation, create a new one
            if automation:
                automation.update(state)
            else:
                automation = Automation(state, self)
                self._automations[automation.id] = automation

    def get_automation(self, automation_id, refresh=False):
        """Get a single automation."""
        if self._automations is None:
            self.get_automations()
            refresh = False

        automation = self._automations.get(str(automation_id))

        if automation and refresh:
            automation.refresh()

        return automation

    def get_alarm(self, area='1', refresh=False):
        """Shortcut method to get the alarm device."""
        return self.get_device(ALARM.id(area), refresh)

    def set_default_mode(self, default_mode):
        """Set the default mode when alarms are turned 'on'."""
        if default_mode.lower() not in ('away', 'home'):
            raise jaraco.abode.Exception(ERROR.INVALID_DEFAULT_ALARM_MODE)

        self._default_alarm_mode = default_mode.lower()

    def set_setting(self, name, value, area='1'):
        """Set an abode system setting to a given value."""
        setting = settings.Setting.load(name.lower(), value, area)
        return self.send_request(method="put", path=setting.path, data=setting.data)

    def acknowledge_timeline_event(self, timeline_id):
        """Acknowledge/verify a timeline alarm event."""
        return self._process_timeline_event(
            timeline_id,
            urls.timeline_verify_alarm,
            'acknowledged',
        )

    def dismiss_timeline_event(self, timeline_id):
        """Dismiss/ignore a timeline alarm event."""
        return self._process_timeline_event(
            timeline_id,
            urls.timeline_ignore_alarm,
            'dismissed',
        )

    def _process_timeline_event(self, timeline_id, url_func, action):
        """Process a timeline event (acknowledge or dismiss).

        Args:
            timeline_id: ID of the timeline event to process
            url_func: Function to generate the URL (e.g., urls.timeline_verify_alarm)
            action: Action description for logging ('acknowledged' or 'dismissed')

        Returns:
            True if successful, raises exception otherwise
        """
        if not timeline_id:
            raise jaraco.abode.Exception(ERROR.MISSING_TIMELINE_ID)

        timeline_id = str(timeline_id)
        url = url_func(timeline_id)

        response = self._send_request('post', url, raise_on_error=False)

        if response is None:
            raise jaraco.abode.Exception(ERROR.REQUEST)

        log.debug('Timeline Event URL (post): %s', url)
        log.debug('Timeline Event Response: %s', response.text)

        # Check if request was successful
        if response.status_code < 400:
            response_object = response.json()

            if not all(key in response_object for key in ('code', 'message', 'tid')):
                raise jaraco.abode.Exception(ERROR.ACK_TIMELINE_RESPONSE)

            if str(response_object.get('tid')) != timeline_id:
                raise jaraco.abode.Exception(ERROR.ACK_TIMELINE_RESPONSE)

            log.info('Timeline event %s %s', timeline_id, action)
            return True

        # Handle error responses
        try:
            error_response = response.json()
            error_code = error_response.get('errorCode')
            error_message = error_response.get('message', 'Unknown error')

            if error_code == ERROR.TIMELINE_EVENT_ALREADY_PROCESSED:
                log.info(
                    'Timeline event %s already %s: %s',
                    timeline_id,
                    action,
                    error_message,
                )
                return True
            else:
                log.error(
                    'Failed to %s timeline event %s (code %s): %s',
                    action.rstrip('ed'),
                    timeline_id,
                    error_code,
                    error_message,
                )
                raise jaraco.abode.Exception(ERROR.REQUEST)
        except (ValueError, KeyError):
            log.error(
                'Failed to %s timeline event %s: unexpected response format',
                action.rstrip('ed'),
                timeline_id,
            )
            raise jaraco.abode.Exception(ERROR.REQUEST)

    def get_timeline_events(self, size=10):
        """Fetch recent timeline events.

        Args:
            size (int): Number of recent events to fetch (default 10)

        Returns:
            list: List of timeline event dictionaries
        """
        response = self.send_request("get", f"{urls.TIMELINE}?size={size}")

        log.debug("Get Timeline Events URL (get): %s", urls.TIMELINE)
        log.debug("Get Timeline Events Response: %s", response.text)

        timeline_events = response.json()

        if not isinstance(timeline_events, list):
            log.warning('Unexpected timeline response format: %s', type(timeline_events))
            return []

        log.info('Fetched %d recent timeline events', len(timeline_events))
        return timeline_events

    def get_test_mode(self):
        """Get the current test mode status from the security panel."""
        response = self.send_request("get", urls.SECURITY_PANEL)

        log.debug("Get Test Mode URL (get): %s", urls.SECURITY_PANEL)
        log.debug("Get Test Mode Response: %s", response.text)

        response_object = response.json()

        # Test mode status is in attributes.cms.testModeActive
        test_mode_active = (
            response_object.get('attributes', {})
            .get('cms', {})
            .get('testModeActive', False)
        )

        log.info('Test mode is currently: %s', 'enabled' if test_mode_active else 'disabled')

        return test_mode_active

    def set_test_mode(self, enabled):
        """
        Set the test mode for the monitoring service.

        When enabled, any triggered alarms will not be dispatched to monitoring service.
        Test mode automatically turns off after 30 minutes.

        Args:
            enabled: Boolean, True to enable test mode, False to disable

        Returns:
            Dict with the updated CMS settings
        """
        if not isinstance(enabled, bool):
            raise jaraco.abode.Exception(ERROR.INVALID_TEST_MODE_VALUE)

        response = self.send_request(
            'post', urls.CMS_SETTINGS, data={'testModeActive': enabled}
        )

        log.debug('Set Test Mode URL (post): %s', urls.CMS_SETTINGS)
        log.debug('Set Test Mode Response: %s', response.text)

        response_object = response.json()

        if 'testModeActive' not in response_object:
            raise jaraco.abode.Exception(ERROR.SET_TEST_MODE_RESPONSE)

        if response_object.get('testModeActive') != enabled:
            raise jaraco.abode.Exception(ERROR.SET_TEST_MODE_RESPONSE)

        log.info('Test mode set to: %s', 'enabled' if enabled else 'disabled')

        return response_object

    def send_request(self, method, path, headers=None, data=None):
        """Send requests to Abode."""
        attempt = functools.partial(self._send_request, method, path, headers, data)
        return jaraco.functools.retry_call(
            attempt,
            retries=1,
            cleanup=self.login,
            trap=(jaraco.abode.Exception),
        )

    def _send_request(self, method, path, headers=None, data=None, raise_on_error=True):
        if not self._token:
            self.login()

        if not headers:
            headers = {}

        headers['Authorization'] = 'Bearer ' + self._oauth_token
        headers['ABODE-API-KEY'] = self._token

        try:
            response = getattr(self._session, method)(path, headers=headers, json=data)

            if response and response.status_code < 400:
                return response

            if not raise_on_error:
                return response
        except RequestException:
            log.info("Abode connection reset...")
            if not raise_on_error:
                return None

        raise jaraco.abode.Exception(ERROR.REQUEST)

    @property
    def default_mode(self):
        """Get the default mode."""
        return self._default_alarm_mode

    @property
    def events(self):
        """Get the event controller."""
        return self._event_controller

    @property
    def uuid(self):
        """Get the UUID."""
        return self._session.cookies['uuid']

    def _get_session(self):
        # Perform a generic update so we know we're logged in
        self.send_request("get", urls.PANEL)

        return self._session
