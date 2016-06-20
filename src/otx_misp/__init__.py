from __future__ import unicode_literals

import logging
import time
from datetime import datetime
import collections

import pymisp
import requests
from .otx import OTXv2

__version__ = "0.2.2"

# Disable verify SSL warnings
requests.packages.urllib3.disable_warnings()

# Get the log handler
log = logging.getLogger('oxt_misp')


class ImportException(Exception):
    pass


def get_pulses(otx_api_key, from_timestamp=None):
    """
    Get the Pulses from Alienvault OTX

    :param otx_api_key: Alienvault OTX API key
    :type otx_api_key: string
    :param from_timestamp: only downlaod Pulses after this Ddate/time (None for all Pulses)
    :type from_timestamp: :class:`datetine.datetine` or ISO string or Unix tinestamp
    :return: a list of Pulses (dict)
    """
    otx = OTXv2(otx_api_key)
    if from_timestamp is None:
        log.debug("Retrieving all Pulses (no timestamp)")
        pulses = otx.getall()
    elif isinstance(from_timestamp, int):
        dt = datetime.fromtimestamp(from_timestamp)
        from_timestamp = dt.isoformat()
        pulses = otx.getsince(from_timestamp)
    elif isinstance(from_timestamp, datetime):
        from_timestamp = from_timestamp.isoformat()
        pulses = otx.getsince(from_timestamp)
    elif isinstance(from_timestamp, basestring):
        pulses = otx.getsince(from_timestamp)
    else:
        raise ValueError("'from_timestamp' must be 'None', a datetime object or an ISO date string")
    return pulses


def get_pulses_iter(otx_api_key, from_timestamp=None):
    """
    Get the Pulses from Alienvault OTX

    :param otx_api_key: Alienvault OTX API key
    :type otx_api_key: string
    :param from_timestamp: only downlaod Pulses after this Ddate/time (None for all Pulses)
    :type from_timestamp: :class:`datetine.datetine` or ISO string or Unix tinestamp
    :return: a list of Pulses (dict)
    """
    otx = OTXv2(otx_api_key)
    if from_timestamp is None:
        log.debug("Retrieving all Pulses (no timestamp)")
        return otx.getall()
    elif isinstance(from_timestamp, int):
        dt = datetime.fromtimestamp(from_timestamp)
        from_timestamp = dt.isoformat()
    elif isinstance(from_timestamp, datetime):
        from_timestamp = from_timestamp.isoformat()
    elif not isinstance(from_timestamp, basestring):
        raise ValueError("'from_timestamp' must be 'None', a datetime object or an ISO date string")
    return otx.getsince_iter(from_timestamp)

import inspect
def create_events(pulse_or_list, author=False, server=False, key=False, misp=False, distribution=0, threat_level=4,
                  analysis=2, publish=True):
    """
    Parse a Pulse or a list of Pulses and add it/them to MISP if server and key are present

    :param pulse_or_list: a Pulse or list of Pulses as returned by `get_pulses`
    :param author: Prepend the author to the Pulse name
    :type author: Boolean
    :param server: MISP server URL
    :param key: MISP API key
    :param misp: MISP connection object
    :type misp: :class:`pymisp.PyMISP`
    :param distribution: distribution of the MISP event (0-4)
    :param threat_level: threat level of the MISP object (1-4)
    :param analysis: analysis stae of the MISP object (0-2)
    :param publish: Is the MISP event should be published?
    :type publish: Boolean
    :return: a dict or a list of dict with the selected attributes
    """
    if not misp and (server and key):
        log.debug("Connection to MISP instance: {}".format(server))
        try:
            misp = pymisp.PyMISP(server, key, False, 'json')
        except pymisp.PyMISPError as ex:
            raise ImportException("Cannot connect ot MISP instance: {}".format(ex.message))
        except Exception as ex:
            raise ImportException("Cannot connect ot MISP instance, unknown exception: {}".format(ex.message))
    if isinstance(pulse_or_list, (list, tuple)) or inspect.isgenerator(pulse_or_list):
        return [create_events(pulse, author=author, server=server, key=key, misp=misp, distribution=distribution,
                              threat_level=threat_level, analysis=analysis, publish=publish) for pulse in pulse_or_list]
    pulse = pulse_or_list
    if author:
        event_name = pulse['author_name'] + ' | ' + pulse['name']
    else:
        event_name = pulse['name']
    dt = datetime.strptime(pulse['modified'], '%Y-%m-%dT%H:%M:%S.%f')
    event_date = dt.strftime('%Y-%m-%d')
    log.info("## {name} - {date}".format(name=event_name, date=event_date))
    result_event = {
        'name': event_name,
        'date': event_date,
        'attributes': {
            'hashes': {
                'md5': list(),
                'sha1': list(),
                'sha256': list(),
                'imphash': list(),
                'pehash': list()
            },
            'hostnames': list(),
            'domains': list(),
            'urls': list(),
            'ips': list(),
            'emails': list(),
            'mutexes': list(),
            'references': list(),
            'cves': list()
        },
    }

    if misp:
        event = misp.new_event(distribution, threat_level, analysis, event_name, date=event_date, published=publish)
        time.sleep(0.2)

    if 'references' in pulse:
        for reference in pulse['references']:
            log.info("\t - Adding external analysis link: {}".format(reference))
            if misp:
                misp.add_named_attribute(event, 'External analysis', 'link', reference)
            result_event['attributes']['references'].append(reference)

    for ind in pulse['indicators']:
        ind_type = ind['type']
        ind_val = ind['indicator']

        if ind_type == 'FileHash-SHA256':
            log.info("\t - Adding SH256 hash: {}".format(ind_val))
            if misp:
                misp.add_hashes(event, sha256=ind_val)
            result_event['attributes']['hashes']['sha256'].append(ind_val)

        elif ind_type == 'FileHash-SHA1':
            log.info("\t - Adding SHA1 hash: {}".format(ind_val))
            if misp:
                misp.add_hashes(event, sha1=ind_val)
            result_event['attributes']['hashes']['sha1'].append(ind_val)

        elif ind_type == 'FileHash-MD5':
            log.info("\t - Adding MD5 hash: {}".format(ind_val))
            if misp:
                misp.add_hashes(event, md5=ind_val)
            result_event['attributes']['hashes']['md5'].append(ind_val)

        elif ind_type == 'URI' or ind_type == 'URL':
            log.info("\t - Adding URL: {}".format(ind_val))
            if misp:
                misp.add_url(event, ind_val)
            result_event['attributes']['urls'].append(ind_val)

        elif ind_type == 'domain':
            log.info("\t - Adding domain: {}".format(ind_val))
            if misp:
                misp.add_domain(event, ind_val)
            result_event['attributes']['domains'].append(ind_val)

        elif ind_type == 'hostname':
            log.info("\t - Adding hostname: {}".format(ind_val))
            if misp:
                misp.add_hostname(event, ind_val)
            result_event['attributes']['hostnames'].append(ind_val)

        elif ind_type == 'IPv4' or ind_type == 'IPv6':
            log.info("\t - Adding ip: {}".format(ind_val))
            if misp:
                misp.add_ipdst(event, ind_val)
            result_event['attributes']['ips'].append(ind_val)

        elif ind_type == 'email':
            log.info("\t - Adding email: {}".format(ind_val))
            if misp:
                misp.add_email_dst(event, ind_val)
            result_event['attributes']['emails'].append(ind_val)

        elif ind_type == 'Mutex':
            log.info("\t - Adding mutex: {}".format(ind_val))
            if misp:
                misp.add_mutex(event, ind_val)
            result_event['attributes']['mutexes'].append(ind_val)

        elif ind_type == 'CVE':
            log.info("\t - Adding CVE: {}".format(ind_val))
            if misp:
                misp.add_named_attribute(event, 'External analysis', 'vulnerability', ind_val)
            result_event['attributes']['cves'].append(ind_val)

        elif ind_type == 'FileHash-IMPHASH':
            log.info("\t - Adding IMPHASH hash: {}".format(ind_val))
            if misp:
                misp.add_named_attribute(event, 'Artifacts dropped', 'imphash', ind_val)
            result_event['attributes']['hashes']['imphash'].append(ind_val)

        elif ind_type == 'FileHash-PEHASH':
            log.info("\t - Adding PEHASH hash: {}".format(ind_val))
            if misp:
                misp.add_named_attribute(event, 'Artifacts dropped', 'pehash', ind_val)
            result_event['attributes']['hashes']['pehash'].append(ind_val)

        else:
            log.warning("Unsupported indicator type: %s" % ind_type)

    if misp and publish:
        event['Event']['published'] = False
        misp.publish(event)
    return result_event
