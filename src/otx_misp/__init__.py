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

__version__ = "1.4.2"

# Try to disable verify SSL warnings
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Get the log handler
log = logging.getLogger('otx_misp')


class ImportException(Exception):
    pass

# MISP instance version
_misp_server_version = None

# Cache to hold all MISP tags available in the MISP instance
_otx_tags_cache = None

def misp_server_version(misp):
    """
    Retrieve the MISP instance version
    
    :param misp: MISP connection object
    :type misp: :class:`pymisp.PyMISP`
    :return: MISP instance version as string
    """
    global _misp_server_version
    if _misp_server_version is None:
        version = misp.misp_instance_version
        _misp_server_version = version['version']
    return _misp_server_version

def add_attribute(misp, event, attribute):
    attrs = misp.search(controller='attributes', eventid=event['id'], type=attribute.type, value=attribute.value)
    if (len(attrs) == 0 or len(attrs['Attribute']) == 0):
        misp.add_attribute(event, attribute)
    else:
        log.info("\t - Attribute already exists. Skipping")
      
def tag_event(misp, event, tag):
    """
    Add a tag to a MISP event
    
    :param misp: MISP connection object
    :type misp: :class:`pymisp.PyMISP` 
    :param event: a MISP event
    :param tag: tag to add
    :return: None
    """
    global _otx_tags_cache
    for exist_tag in _otx_tags_cache:
        if exist_tag['name'] == tag:
            tag_id = exist_tag['id']
            if 'Tag' in event:
                for evt_tag in event['Tag']:
                    if tag_id == evt_tag['id']:
                        log.info("\t - Tag already exists. Skipping:{}".format(tag))
                        return
            break
    misp.tag(event['uuid'], tag)

def get_pulses(otx_api_key, from_timestamp=None):
    """
    Get the Pulses from Alienvault OTX

    :param otx_api_key: Alienvault OTX API key
    :type otx_api_key: string
    :param from_timestamp: only download Pulses after this date/time (None for all Pulses)
    :type from_timestamp: :class:`datetime.datetime` or ISO string or Unix timestamp
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
    :param from_timestamp: only download Pulses after this date/time (None for all Pulses)
    :type from_timestamp: :class:`datetime.datetime` or ISO string or Unix timestamp
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
                  analysis=2, publish=True, tlp=True, discover_tags=False, to_ids=False, author_tag=False,
                  bulk_tag=None, dedup_titles=False, stop_on_error=False):
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
    :param to_ids: Flag pulse attributes as being sent to an IDS
    :type to_ids: Boolean
    :param author_tag: Add the pulse author as an event tag
    :type author_tag: Boolean
    :param bulk_tag: A tag that will be added to all events for categorization (e.g. OTX)
    :type bulk_tag: String
    :param dedup_titles: Search MISP for an existing event title and update it, rather than create a new one
    :type dedup_titles: Boolean
    :return: a dict or a list of dict with the selected attributes
    """
    if not misp and (server and key):
        log.debug("Connection to MISP instance: {}".format(server))
        try:
            misp = pymisp.ExpandedPyMISP(server, key, ssl=False)
        except pymisp.PyMISPError as ex:
            raise ImportException("Cannot connect to MISP instance: {}".format(ex.message))
        except Exception as ex:
            raise ImportException("Cannot connect to MISP instance, unknown exception: {}".format(ex.message))
        # Let's load in cache all MISP tags available on the instance
        global _otx_tags_cache
        if _otx_tags_cache is None:
            _otx_tags_cache = misp.tags()

    if discover_tags:
        def get_tag_name(complete):
            parts = complete.split('=')
            if not len(parts):
                return complete
            last = parts[-1]
            if not len(last):
                return complete
            if last[0] == '"':
                last = last[1:]
            if last[-1] == '"':
                last = last[:-1]
            return last.lower()
        tags = dict()
        for tag in _otx_tags_cache:
            tags[get_tag_name(tag['name'])] = tag['name']
        misp.discovered_tags = tags

    if isinstance(pulse_or_list, (list, tuple)) or inspect.isgenerator(pulse_or_list):
        misp_events = []
        for pulse in pulse_or_list:
            try:
                misp_event = create_events(pulse, author=author, server=server, key=key, misp=misp,
                                           distribution=distribution, threat_level=threat_level, analysis=analysis,
                                           publish=publish, tlp=tlp, to_ids=to_ids, author_tag=author_tag,
                                           bulk_tag=bulk_tag, dedup_titles=dedup_titles, stop_on_error=stop_on_error)
                misp_events.append(misp_event)
            except Exception as ex:
                if stop_on_error:
                    raise
                name = ''
                if pulse and 'name' in pulse:
                    name = pulse['name']
                log.error("Cannot import pulse {}: {}".format(name, ex))
        return misp_events

    pulse = pulse_or_list
    if author:
        event_name = pulse['author_name'] + ' | ' + pulse['name']
    else:
        event_name = pulse['name']
    event_name = event_name.strip()
    try:
        dt = date_parser.parse(pulse['created'])
    except (ValueError, OverflowError):
        log.error("Cannot parse Pulse 'created' date.")
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
            'cves': list(),
            'filenames': list(),
            'yara': list()
        },
    }

    if misp:
        if not dedup_titles:
            event = pymisp.MISPEvent()
            event.distribution = distribution
            event.threat_level_id = threat_level
            event.analysis = analysis
            event.info = event_name
            event.date = dt
            event = misp.add_event(event)['Event']
        else:
            event = ''
            # Search MISP for the title
            result = misp.search(eventinfo=event_name, metadata=True)
            if len(result) == 0:
                event = pymisp.MISPEvent()
                event.distribution = distribution
                event.threat_level = threat_level
                event.analysis = analysis
                event.info = event_name
                event.set_date(dt)
                event = misp.add_event(event)['Event']
            else:
                for evt in result:
                    # If it exists, set 'event' to the event
                    if evt['Event']['info'] == event_name:
                        if 'SharingGroup' in evt['Event']:
                            del evt['Event']['SharingGroup']  # This deletes the SharingGroup from the list, thx SparkyNZL
                        event = evt['Event']
                        break
                if event == '':
                    # Event not found, even though search results were returned
                    # Build new event
                    event = pymisp.MISPEvent()
                    event.distribution = distribution
                    event.threat_level = threat_level
                    event.analysis = analysis
                    event.info = event_name
                    event.set_date(dt)
                    misp.add_event(event)
        time.sleep(0.2)
        if tlp:
            tag = None
            if 'TLP' in pulse:
                tag = "tlp:{}".format(pulse['TLP'])
            elif 'tlp' in pulse:
                tag = "tlp:{}".format(pulse['tlp'])
            if tag is not None:
                log.info("\t - Adding tag: {}".format(tag))
                tag_event(misp, event, tag)
                result_event['tags'].append(tag)

        if author_tag:
            tag_event(misp, event, pulse['author_name'])

        if bulk_tag is not None:
            tag_event(misp, event, bulk_tag)

    if misp and hasattr(misp, 'discovered_tags') and 'tags' in pulse:
        for pulse_tag in pulse['tags']:
            if pulse_tag.lower() in misp.discovered_tags:
                tag = misp.discovered_tags[pulse_tag.lower()]
                log.info("\t - Adding tag: {}".format(tag))
                tag_event(misp, event, tag)
                result_event['tags'].append(tag)
                
    if 'references' in pulse:
        for reference in pulse['references']:
            if reference:
                log.info("\t - Adding external analysis link: {}".format(reference))
                if misp:
                    a = pymisp.MISPAttribute()
                    a.category = "External analysis"
                    a.type = 'link'
                    a.value = reference
                    add_attribute(misp, event, a)
                result_event['attributes']['references'].append(reference)

    if misp and 'description' in pulse and isinstance(pulse['description'], six.text_type) and pulse['description']:
        log.info("\t - Adding external analysis comment")
        a = pymisp.MISPAttribute()
        a.category = 'External analysis'
        a.type = 'comment'
        a.value = pulse['description']
        add_attribute(misp, event, a)

    for ind in pulse['indicators']:
        ind_type = ind['type']
        ind_val = ind['indicator']
        a = pymisp.MISPAttribute()        
        a.value = ind_val
        a.to_ids = to_ids

        if 'description' in ind and isinstance(ind['description'], six.text_type) and ind['description']:
            a.comment = ind['description']
            
        if ind_type == 'FileHash-SHA256':
            log.info("\t - Adding SHA256 hash: {}".format(ind_val))
            a.category = 'Artifacts dropped'            
            a.type = 'sha256'
            add_attribute(misp, event, a)                        
            result_event['attributes']['hashes']['sha256'].append(ind_val)

        elif ind_type == 'FileHash-SHA1':
            log.info("\t - Adding SHA1 hash: {}".format(ind_val))
            a.category = 'Artifacts dropped'                        
            a.type = 'sha1'
            add_attribute(misp, event, a)                        
            result_event['attributes']['hashes']['sha1'].append(ind_val)

        elif ind_type == 'FileHash-MD5':
            log.info("\t - Adding MD5 hash: {}".format(ind_val))
            a.category = 'Artifacts dropped'                        
            a.type = 'md5'
            add_attribute(misp, event, a)                        
            result_event['attributes']['hashes']['md5'].append(ind_val)

        elif ind_type == 'FileHash-IMPHASH':
            log.info("\t - Adding IMPHASH hash: {}".format(ind_val))
            a.category = 'Artifacts dropped'                        
            a.type = 'imphash'
            add_attribute(misp, event, a)                        
            result_event['attributes']['hashes']['imphash'].append(ind_val)

        elif ind_type == 'FileHash-PEHASH':
            log.info("\t - Adding PEHASH hash: {}".format(ind_val))
            a.category = 'Artifacts dropped'                                    
            a.type = 'pehash'
            add_attribute(misp, event, a)                        
            result_event['attributes']['hashes']['pehash'].append(ind_val)
            
        elif ind_type == 'YARA':
            ind_title = ind.get('title', ind_val)
            ind_desc = ind.get('description', '')
            if ind_title == '':
                ind_title = ind_val
                if not ind_desc == '':
                    a.comment = ind_desc
            else:
                a.comment = "{} {}".format(ind_title, ind_desc)
            ind_val = ind.get('content', None)
            if ind_val is None or ind_val == "":
                log.warning("YARA indicator is empty: %s" % ind_title)
                continue
            log.info("\t - Adding YARA rule: {}".format(ind_title))
            a.category = 'Artifacts dropped'                                    
            a.type = 'yara'
            a.value = ind_val
            add_attribute(misp, event, a)                        
            result_event['attributes']['yara'].append({'title': ind_title, 'content': ind_val})

        elif ind_type == 'Mutex':
            log.info("\t - Adding mutex: {}".format(ind_val))
            a.category = 'Artifacts dropped'                                    
            a.type = 'mutex'
            add_attribute(misp, event, a)                        
            result_event['attributes']['mutexes'].append(ind_val)

        elif ind_type == 'FilePath':
            log.info("\t - Adding filename: {}".format(ind_val))
            a.category = 'Artifacts dropped'                                    
            a.type = 'filename'
            add_attribute(misp, event, a)                        
            result_event['attributes']['filenames'].append(ind_val)
            
        elif ind_type == 'URI' or ind_type == 'URL':
            log.info("\t - Adding URL: {}".format(ind_val))
            a.category = 'Network activity'            
            a.type = 'url'
            add_attribute(misp, event, a)                        
            result_event['attributes']['urls'].append(ind_val)

        elif ind_type == 'domain':
            log.info("\t - Adding domain: {}".format(ind_val))
            a.category = 'Network activity'                        
            a.type = 'domain'
            add_attribute(misp, event, a)                        
            result_event['attributes']['domains'].append(ind_val)

        elif ind_type == 'hostname':
            log.info("\t - Adding hostname: {}".format(ind_val))
            a.category = 'Network activity'                        
            a.type = 'hostname'
            add_attribute(misp, event, a)                        
            result_event['attributes']['hostnames'].append(ind_val)

        elif ind_type == 'IPv4' or ind_type == 'IPv6':
            log.info("\t - Adding ip: {}".format(ind_val))
            a.category = 'Network activity'                        
            a.type = 'ip-dst'
            add_attribute(misp, event, a)                        
            result_event['attributes']['ips'].append(ind_val)

        elif ind_type == 'email':
            log.info("\t - Adding email: {}".format(ind_val))
            a.category = 'Network activity'                        
            a.type = 'email-dst'
            result_event['attributes']['emails'].append(ind_val)
            add_attribute(misp, event, a)                        

        elif ind_type == 'CVE':
            log.info("\t - Adding CVE: {}".format(ind_val))
            a.type = 'External analysis'
            a.type = 'vulnerability'
            add_attribute(misp, event, a)            
            result_event['attributes']['cves'].append(ind_val)
            
        else:
            log.warning("Unsupported indicator type: %s" % ind_type)

    if misp and publish:
        misp.publish(event)
    return result_event
