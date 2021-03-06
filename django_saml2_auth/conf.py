from django_saml2_auth.utils import get_reverse
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from django.conf import settings


def get_saml_client(domain):
    sp_config = get_saml_config(domain)
    saml_client = Saml2Client(config=sp_config)
    return saml_client


def get_saml_config(domain):
    settings = parse_settings(domain)
    sp_config = Saml2Config()
    sp_config.load(settings)
    sp_config.allow_unknown_attributes = True
    return sp_config


def parse_settings(domain):
    acs_url = domain + get_reverse(['acs', 'django_saml2_auth:acs'])

    saml_settings = {
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                },
                'allow_unsolicited': True,
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }

    if 'METADATA' in settings.SAML2_AUTH:
        saml_settings['metadata'] = settings.SAML2_AUTH['METADATA']
    elif 'METADATA_AUTO_CONF_URL' in settings.SAML2_AUTH['METADATA_AUTO_CONF_URL']:
        saml_settings['metadata'] = {
            'remote': [
                {
                    'url': settings.SAML2_AUTH['METADATA_AUTO_CONF_URL']
                }
            ]
        }
    else:
        raise Exception('Invalid configuration, either "METADATA" or "METADATA_AUTO_CONF_URL" is required')


    if 'ENTITY_ID' in settings.SAML2_AUTH:
        saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']

    if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
        saml_settings['service']['sp']['name_id_format'] = settings.SAML2_AUTH['NAME_ID_FORMAT']

    return saml_settings
