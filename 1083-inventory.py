import jmespath
import json


def rule_1083(entries):
    device_ids = jmespath.search(
        "report_entries[?ruleid=='1083'].problem_devices[]", entries)
    return device_ids


def get_hosts(devices, audited_devices):
    host_list = []
    for device in devices:
        host = jmespath.search(
            "audited_devices[?device_oeid=='{}'].hostname".format(
                device), audited_devices)
        if host:
            host = host.pop()
            host_list.append(host)
    return host_list


if __name__ == "__main__":
    with open('data/netdoctor_report_entries_data.json', 'r') as fh:
        entries = json.load(fh)
    devices_1083 = rule_1083(entries)
    with open('data/netdoctor_audited_devices_data.json', 'r') as fh:
        audited_devices = json.load(fh)
    inventory_list = get_hosts(devices_1083, audited_devices)
    print(inventory_list)
