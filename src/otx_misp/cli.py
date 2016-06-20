"""
Module that contains the command line app.

Why does this file exist, and why not put this in __main__?

  You might be tempted to import things from __main__ later, but that will cause
  problems: the code will get executed twice:

  - When you run `python -motx_misp` python will execute
    ``__main__.py`` as a script. That means there won't be any
    ``otx_misp.__main__`` in ``sys.modules``.
  - When you import __main__ it will get executed again (as a module) because
    there's no ``otx_misp.__main__`` in ``sys.modules``.

  Also see (1) from http://click.pocoo.org/5/setuptools/#setuptools-integration
"""
import argparse
import logging
import os.path
import sys
from datetime import datetime

from dateutil import parser as date_parser

from otx_misp.configuration import Configuration, ConfigurationError
from otx_misp import get_pulses, create_events
from .otx import InvalidAPIKey, BadRequest

log = logging.getLogger('oxt_misp')
console_handler = logging.StreamHandler()
log.addHandler(console_handler)


def timestamp(argument):
    try:
        unix_ts = int(argument)
        date = datetime.utcfromtimestamp(unix_ts)
    except ValueError:
        date = date_parser.parse(argument)
    return date


misp_distributions = ['organisation', 'community', 'connected', 'all']
misp_threat_levels = ['high', 'medium', 'low', 'undefined']
misp_analysis = ['initial', 'ongoing', 'completed']


def get_misp_type(choices, bias=0):
    def misp_type(argument):
        try:
            dist = int(argument)
        except ValueError:
            argument = argument.lower()
            dist = choices.index(argument)
        if 0 <= dist < len(choices):
            return dist + bias
        raise ValueError

    return misp_type


parser = argparse.ArgumentParser(description='Downloads OTX pulses and add them to MISP.')
parser.add_argument('-o', '--otx', help="Alienvault OTX API key", dest='otx')
parser.add_argument('-s', '--server', help="MISP server URL")
parser.add_argument('-m', '--misp', help='MISP API key', dest='misp')
parser.add_argument('-t', '--timestamp', help='Last import as Date/Time ISO format or UNIX timestamp', type=timestamp,
                    dest='timestamp', default=datetime.utcfromtimestamp(0))
parser.add_argument('-c', '--config-file', dest='config')
parser.add_argument('-w', '--write-config', help='Write the configuration file', action='store_true')
parser.add_argument('-a', '--author', help='Add the Pulse author name in the MISP Info field', action='store_true')
parser.add_argument('-u', '--update-timestamp', help='Updates the timestamp in the configuaration file',
                    action='store_true')
parser.add_argument('-n', '--no-publish', help="Don't publish the MISP event" , action='store_false', dest='publish')
parser.add_argument('-d', '--dry-run', help="Fetch the pulses but don't create MISP events. Use -v[v] to see details.",
                    action='store_true', dest='simulate')
parser.add_argument("-v", "--verbose", dest="verbose",
                    action="count", default=0,
                    help="Verbosity, repeat to increase the verbosity level.")
parser.add_argument('--distribution',
                    help="MISP distribution of events ({}), default: {}".format(','.join(misp_distributions),
                                                                                misp_distributions[0]),
                    type=get_misp_type(misp_distributions), default=None)
parser.add_argument('--threat-level',
                    help="MISP threat level of events ({}), default: {}".format(','.join(misp_threat_levels),
                                                                                misp_threat_levels[3]),
                    type=get_misp_type(misp_threat_levels, bias=1), default=None)
parser.add_argument('--analysis',
                    help="MISP analysis state of events ({}), default: {}".format(','.join(misp_analysis),
                                                                                  misp_analysis[2]),
                    type=get_misp_type(misp_analysis), default=None)


def main(args=None):
    args = parser.parse_args(args=args)
    if args.verbose == 1:
        log.setLevel('WARNING')
    elif args.verbose == 2:
        log.setLevel('INFO')
    elif args.verbose >= 3:
        log.setLevel('DEBUG')
    else:
        log.setLevel('ERROR')
    if args.simulate:
        if (not args.config or not os.path.isfile(args.config)) and not args.otx:
            log.error("You must either give an existing config file or your OTX API key with '--dry-run'.")
            sys.exit(4)
    elif (not args.config or not os.path.isfile(args.config)) and not (args.otx and args.server and args.misp):
        log.error("You must either give an existing config file or your API keys and the MISP server URL.")
        sys.exit(2)
    try:
        config = Configuration(args)
    except Exception as ex:
        log.error(ex.message)
        sys.exit(5)

    try:
        pulses = get_pulses(config.otx, from_timestamp=config.timestamp.isoformat())
    except InvalidAPIKey:
        log.error("Wrong API key: '{}'".format(config.otx))
        sys.exit(11)
    except ValueError as ex:
        log.error("Cannot use last import timestamp '{}'".format(config.timestamp.isoformat()))
        sys.exit(12)
    except BadRequest:
        log.error("Bad request")
        sys.exit(13)
    kwargs = {}
    if not config.simulate:
        kwargs = {
            'server': config.server,
            'key': config.misp,
            'distribution': config.distribution,
            'threat_level': config.threat_level,
            'analysis': config.analysis
        }
        try:
            import pymisp
        except ImportError:
            log.error('PyMISP is not installed. Aborting.')
            sys.exit(20)
    create_events(pulses, author=config.author, **kwargs)

    if config.write_config or config.update_timestamp:
        if args.config:
            with open(args.config, 'w') as f:
                config.write(f)
        else:
            config.write(sys.stdout)
