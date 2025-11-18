BASE = 'https://my.goabode.com/'

LOGIN = '/api/auth2/login'
LOGOUT = '/api/v1/logout'

OAUTH_TOKEN = '/api/auth2/claims'

PARAMS = '/api/v1/devices_beta/'

PANEL = '/api/v1/panel'
SECURITY_PANEL = '/integrations/v1/security-panel'
CMS_SETTINGS = '/integrations/v1/cms/settings'

INTEGRATIONS = '/integrations/v1/devices/'
CAMERA_INTEGRATIONS = '/integrations/v1/camera/'


def panel_mode(area, mode):
    """Create panel URL."""
    return f'/api/v1/panel/mode/{area}/{mode}'


def panel_alarm():
    """Create panel manual alarm URL."""
    return '/integrations/v1/panel/alarm'


DEVICES = '/api/v1/devices'
DEVICE = '/api/v1/devices/{id}'

AREAS = '/api/v1/areas'

SETTINGS = '/api/v1/panel/setting'
SOUNDS = '/api/v1/sounds'
SIREN = '/api/v1/siren'

AUTOMATION = '/integrations/v1/automations/'
AUTOMATION_ID = AUTOMATION + '{id}/'
AUTOMATION_APPLY = AUTOMATION_ID + 'apply'

TIMELINE = '/api/v1/timeline'
TIMELINE_IMAGES_ID = (
    '/api/v1/timeline?device_id={device_id}&dir=next&event_label=Image+Capture&size=1'
)


def timeline_verify_alarm(timeline_id):
    """Create timeline verify alarm URL."""
    return f'/api/v1/timeline/{timeline_id}/verify_alarm'


def timeline_ignore_alarm(timeline_id):
    """Create timeline ignore alarm URL."""
    return f'/api/v1/timeline/{timeline_id}/ignore_alarm'
