from __future__ import unicode_literals

import ConfigParser
import logging
import os.path
from datetime import datetime

from dateutil import parser as date_parser


class ConfigurationError(Exception):
    pass


class Configuration(object):
    """ Object holding the configuration """
    properties = {'otx': True, 'misp': True, 'server': True, 'timestamp': False, 'author': False,
                  'distribution': False, 'threat_level': False, 'analysis': False, 'update_timestamp': False,
                  'publish': False}
    simulation_properties = {'otx': True, 'misp': True, 'server': True, 'timestamp': False,
                             'author': False, 'distribution': False, 'threat_level': False, 'analysis': False,
                             'update_timestamp': False, 'publish': False}
    config_section = 'otx_misp'

    def __init__(self, arguments):
        self.config = ConfigParser.SafeConfigParser(allow_no_value=True)
        if arguments.config and os.path.isfile(arguments.config):
            self.config.read(arguments.config)
        if not self.config.has_section(self.config_section):
            self.config.add_section(self.config_section)
        self.arguments = arguments
        self._populate_config()

    def _populate_config(self):
        if self.arguments.simulate:
            self.properties = self.simulation_properties
        for key, required in self.simulation_properties.items():
            value = getattr(self.arguments, key, None)
            if isinstance(value, bool):
                if value:
                    value = 'yes'
                else:
                    value = 'no'
            elif isinstance(value, (list, tuple)):
                value = ','.join(value)
            elif isinstance(value, datetime):
                value = value.isoformat()
            elif isinstance(value, int):
                value = '{}'.format(value)
            if value is not None:
                self.config.set(self.config_section, key, value)
            if required:
                try:
                    value = self.config.get(self.config_section, key)
                except ConfigParser.NoOptionError:
                    raise ConfigurationError("Missing required parameter: '--{}'".format(key))
                print self.config.get(self.config_section, key)
                if value is None:
                    raise ConfigurationError("Missing required parameter: '--{}'".format(key))

    def __getattr__(self, item):
        if item not in self.arguments:
            raise AttributeError
        value = getattr(self.arguments, item, None)
        if item not in self.properties:
            return value
        if isinstance(value, bool):
            return self.config.getboolean(self.config_section, item)
        elif isinstance(value, (list, tuple)):
            parameter = self.config.get(self.config_section, item)
            return parameter.split(',')
        elif isinstance(value, datetime):
            parameter = self.config.get(self.config_section, item)
            if parameter is not None:
                try:
                    return date_parser.parse(parameter)
                except:
                    pass
        elif isinstance(value, int):
            return self.config.getint(self.config_section, item)
        return self.config.get(self.config_section, item)

    def write(self, fp):
        if self.update_timestamp:
            self.config.set(self.config_section, 'timestamp', datetime.utcnow().isoformat())
        return self.config.write(fp)
