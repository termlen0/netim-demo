from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
    name: netim_inventory
    plugin_type: inventory
    short_description: Returns hosts that match audit rule
    description: Returns hosts that match audit rule
    options:
      plugin:
          description: Name of the plugin
          required: true
          choices: ['netim_inventory']
      rule:
        description: NetIM audit rule(string)
        required: true
      data_files_path:
                  description: Path to Audit output JSON
                  required: true
'''



import json
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.errors import AnsibleError, AnsibleParserError

try:
    import jmespath
except ImportError:
    raise AnsibleError("JMEspath module is required for this plugin")


class InventoryModule(BaseInventoryPlugin):
    NAME = 'netim_inventory'

    def _rule_1083(self, entries):
        device_ids = jmespath.search(
            "report_entries[?ruleid=='1083'].problem_devices[]", entries)
        return device_ids

    def _get_hosts(self, devices, audited_devices):
        host_list = []
        for device in devices:
            host = jmespath.search(
                "audited_devices[?device_oeid=='{}'].hostname".format(
                    device), audited_devices)
            if host:
                host = host.pop()
                host_list.append(host)
        return host_list

    def _populate(self):
        report_entries_path = self.data_path + "/netdoctor_report_entries_data.json"
        audited_devices_path = self.data_path + "/netdoctor_audited_devices_data.json"
        with open(report_entries_path, 'r') as fh:
            entries = json.load(fh)
        if self.rule == "1083":
            devices_1083 = self._rule_1083(entries)
        else:
            raise AnsibleError("This rule is not implemented")
        with open(audited_devices_path, 'r') as fh:
            audited_devices = json.load(fh)
        _hosts = self._get_hosts(devices_1083, audited_devices)
        _group = "devices_" + self.rule
        self.inventory.add_group(_group)
        for hostname in _hosts:
            self.inventory.add_host(host=hostname, group=_group)

    def verify_file(self, path):
        '''return true/false if this is possibly a valid file for this plugin to
consume'''
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current
            # user
            if path.endswith(('netim_inventory.yaml', 'netim_inventory.yml')):
                valid = True
        return valid

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        self._read_config_data(path)
        try:
            self.plugin = self.get_option('plugin')
            self.rule = self.get_option('rule')
            self.data_path = self.get_option('data_files_path')
        except Exception as e:
            raise AnsibleParserError(
                'All correct options required: {}'.format(e))
        self._populate()
