from __future__ import unicode_literals

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

import logging
import os.path
from datetime import datetime

import io
from dateutil import parser as date_parser


class ConfigurationError(Exception):
    pass


class Configuration(object):
    """ Object holding the configuration """
    properties = {'otx': True, 'misp': True, 'server': True, 'timestamp': False, 'author': False,
                  'distribution': False, 'threat_level': False, 'analysis': False, 'update_timestamp': False,
                  'publish': False, 'tlp': False, 'discover_tags': False, 'to_ids': False, 'author_tag': False,
                  'bulk_tag': False, 'dedup_titles': False}
    simulation_properties = {'otx': True, 'misp': True, 'server': True, 'timestamp': False, 'author': False,
                             'distribution': False, 'threat_level': False, 'analysis': False, 'update_timestamp': False,
                             'publish': False, 'tlp': False, 'discover_tags': False, 'to_ids': False,
                             'author_tag': False, 'bulk_tag': False, 'dedup_titles': False}
    defaults = {'distribution': 0, 'threat_level': 4, 'analysis': 2, 'timestamp': datetime.utcfromtimestamp(0),
                'update_timestamp': False}
    config_section = 'otx_misp'

    def __init__(self, arguments):
        self.config = configparser.SafeConfigParser(allow_no_value=True)
        if arguments.config and os.path.isfile(arguments.config):
            self.config.read(arguments.config)
        if not self.config.has_section(self.config_section):
            self.config.add_section(self.config_section)
        self.arguments = arguments
        self.original_config = self._clone_config(self.config)
        self._populate_config()

    @staticmethod
    def _clone_config(config):
        clone = configparser.SafeConfigParser(allow_no_value=True)
        for section in config.sections():
            clone.add_section(section)
            for option in config.options(section):
                clone.set(section, option, config.get(section, option))
        return clone

    def _populate_config(self):
        if self.arguments.simulate:
            self.properties = self.simulation_properties
        for key, required in list(self.simulation_properties.items()):
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
                except configparser.NoOptionError:
                    raise ConfigurationError("Missing required parameter: '--{}'".format(key))
                if value is None:
                    raise ConfigurationError("Missing required parameter: '--{}'".format(key))

    def __getattr__(self, item):
        if item not in self.arguments:
            raise AttributeError
        value = getattr(self.arguments, item, None)
        if value is None and item in self.defaults:
            value = self.defaults[item]
        if item not in self.properties or not self.config.has_option(self.config_section, item):
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
        if self.write_config:
            config = self.config
        else:
            config = self.original_config
        if self.update_timestamp:
            config.set(self.config_section, 'timestamp', datetime.utcnow().isoformat())
        return config.write(fp)
