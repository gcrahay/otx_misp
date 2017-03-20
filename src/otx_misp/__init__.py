from __future__ import unicode_literals

import logging
import time
from datetime import datetime
from dateutil import parser as date_parser
import inspect
import six

import pymisp
import requests
from .otx import OTXv2

try:
  basestring
except NameError:
  basestring = str

__version__ = "1.1.1"

# Try to disable verify SSL warnings
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

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
    Get the Pulses from Alienvault OTX and returns a generator

    :param otx_api_key: Alienvault OTX API key
    :type otx_api_key: string
    :param from_timestamp: only downlaod Pulses after this Ddate/time (None for all Pulses)
    :type from_timestamp: :class:`datetine.datetine` or ISO string or Unix tinestamp
    :return: a generator of Pulses (dict)
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


def create_events(pulse_or_list, author=False, server=False, key=False, misp=False, distribution=0, threat_level=4,
                  analysis=2, publish=True, tlp=True, discover_tags=False, to_ids=False):
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
    :param tlp: Add TLP level tag to event
    :type tlp: Boolean
    :param discover_tags: discover MISP tags from Pulse tags
    :type discover_tags: Boolean
    :return: a dict or a list of dict with the selected attributes
    """
    if not misp and (server and key):
        log.debug("Connection to MISP instance: {}".format(server))
        try:
            misp = pymisp.PyMISP(server, key, ssl=False, out_type='json', debug=False)
        except pymisp.PyMISPError as ex:
            raise ImportException("Cannot connect to MISP instance: {}".format(ex.message))
        except Exception as ex:
            raise ImportException("Cannot connect to MISP instance, unknown exception: {}".format(ex.message))
    if discover_tags:
        def get_tag_name(complete):
            parts = complete.split('=')
            if not len(parts):
                return complete
            last = parts[-1]
            if last[0] == '"':
                last = last[1:]
            if last[-1] == '"':
                last = last[:-1]
            return last.lower()
        raw_tags = misp.get_all_tags()
        tags = dict()
        for tag in raw_tags['Tag']:
            tags[get_tag_name(tag['name'])] = tag['name']
        misp.discovered_tags = tags

    if isinstance(pulse_or_list, (list, tuple)) or inspect.isgenerator(pulse_or_list):
        return [create_events(pulse, author=author, server=server, key=key, misp=misp, distribution=distribution,
                              threat_level=threat_level, analysis=analysis, publish=publish, tlp=tlp, to_ids=to_ids)
                for pulse in pulse_or_list]
    pulse = pulse_or_list
    if author:
        event_name = pulse['author_name'] + ' | ' + pulse['name']
    else:
        event_name = pulse['name']
    try:
        dt = date_parser.parse(pulse['modified'])
    except (ValueError, OverflowError):
        log.error("Cannot parse Pulse 'modified' date.")
        dt = datetime.utcnow()
    event_date = dt.strftime('%Y-%m-%d')
    log.info("## {name} - {date}".format(name=event_name, date=event_date))
    result_event = {
        'name': event_name,
        'date': event_date,
        'tags': list(),
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
        if tlp and 'TLP' in pulse:
            tag = "tlp:{}".format(pulse['TLP'])
            log.info("\t - Adding tag: {}".format(tag))
            misp.add_tag(event, tag)
            result_event['tags'].append(tag)

    if misp and hasattr(misp, 'discovered_tags') and 'tags' in pulse:
        for pulse_tag in pulse['tags']:
            if pulse_tag.lower() in misp.discovered_tags:
                tag = misp.discovered_tags[pulse_tag.lower()]
                log.info("\t - Adding tag: {}".format(tag))
                misp.add_tag(event, tag)
                result_event['tags'].append(tag)

    if 'references' in pulse:
        for reference in pulse['references']:
            log.info("\t - Adding external analysis link: {}".format(reference))
            if misp and reference:
                misp.add_named_attribute(event, 'link', reference, category='External analysis')
            result_event['attributes']['references'].append(reference)

    if misp and 'description' in pulse and isinstance(pulse['description'], six.text_type) and pulse['description']:
        log.info("\t - Adding external analysis comment")
        misp.add_named_attribute(event, 'comment', pulse['description'], category='External analysis')

    for ind in pulse['indicators']:
        ind_type = ind['type']
        ind_val = ind['indicator']
        ind_kwargs = {'to_ids': to_ids}

        if 'description' in ind and isinstance(ind['description'], six.text_type) and ind['description']:
            ind_kwargs['comment'] = ind['description']

        if ind_type == 'FileHash-SHA256':
            log.info("\t - Adding SH256 hash: {}".format(ind_val))
            if misp:
                misp.add_hashes(event, sha256=ind_val, **ind_kwargs)
            result_event['attributes']['hashes']['sha256'].append(ind_val)

        elif ind_type == 'FileHash-SHA1':
            log.info("\t - Adding SHA1 hash: {}".format(ind_val))
            if misp:
                misp.add_hashes(event, sha1=ind_val, **ind_kwargs)
            result_event['attributes']['hashes']['sha1'].append(ind_val)

        elif ind_type == 'FileHash-MD5':
            log.info("\t - Adding MD5 hash: {}".format(ind_val))
            if misp:
                misp.add_hashes(event, md5=ind_val, **ind_kwargs)
            result_event['attributes']['hashes']['md5'].append(ind_val)

        elif ind_type == 'URI' or ind_type == 'URL':
            log.info("\t - Adding URL: {}".format(ind_val))
            if misp:
                misp.add_url(event, ind_val, **ind_kwargs)
            result_event['attributes']['urls'].append(ind_val)

        elif ind_type == 'domain':
            log.info("\t - Adding domain: {}".format(ind_val))
            if misp:
                misp.add_domain(event, ind_val, **ind_kwargs)
            result_event['attributes']['domains'].append(ind_val)

        elif ind_type == 'hostname':
            log.info("\t - Adding hostname: {}".format(ind_val))
            if misp:
                misp.add_hostname(event, ind_val, **ind_kwargs)
            result_event['attributes']['hostnames'].append(ind_val)

        elif ind_type == 'IPv4' or ind_type == 'IPv6':
            log.info("\t - Adding ip: {}".format(ind_val))
            if misp:
                misp.add_ipdst(event, ind_val, **ind_kwargs)
            result_event['attributes']['ips'].append(ind_val)

        elif ind_type == 'email':
            log.info("\t - Adding email: {}".format(ind_val))
            if misp:
                misp.add_email_dst(event, ind_val, **ind_kwargs)
            result_event['attributes']['emails'].append(ind_val)

        elif ind_type == 'Mutex':
            log.info("\t - Adding mutex: {}".format(ind_val))
            if misp:
                misp.add_mutex(event, ind_val, **ind_kwargs)
            result_event['attributes']['mutexes'].append(ind_val)

        elif ind_type == 'CVE':
            log.info("\t - Adding CVE: {}".format(ind_val))
            if misp:
                misp.add_named_attribute(event, 'vulnerability', ind_val, category='External analysis', **ind_kwargs)
            result_event['attributes']['cves'].append(ind_val)

        elif ind_type == 'FileHash-IMPHASH':
            log.info("\t - Adding IMPHASH hash: {}".format(ind_val))
            if misp:
                misp.add_named_attribute(event, 'imphash', ind_val, category='Artifacts dropped', **ind_kwargs)
            result_event['attributes']['hashes']['imphash'].append(ind_val)

        elif ind_type == 'FileHash-PEHASH':
            log.info("\t - Adding PEHASH hash: {}".format(ind_val))
            if misp:
                misp.add_named_attribute(event, 'pehash', ind_val, category='Artifacts dropped', **ind_kwargs)
            result_event['attributes']['hashes']['pehash'].append(ind_val)

        else:
            log.warning("Unsupported indicator type: %s" % ind_type)

    if misp and publish:
        event['Event']['published'] = False
        misp.publish(event)
    return result_event
