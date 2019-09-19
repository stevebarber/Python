#!/usr/bin/env python

"""
pan-dynamic-objects.py
==========================

Template script to interact with firewalls and Panorama

-i, --ip, help="Name or IP address of the firewall/Panorama"
-u, --username, help="User login"
-p, --password, help="Login password"

"""

import sys
import signal
import getpass
import argparse
import csv
from lxml import etree

from pandevice import base, panorama, objects
#from netaddr import *
from variables import *

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="Name or IP address of the firewall/Panorama")
parser.add_argument("-u", "--username", help="User login")
parser.add_argument("-p", "--password", help="Login password")
args = parser.parse_args()

print('\n')

try:
    if args.ip:
        ip = args.ip
    else:
        ip = input("Enter the name or IP of the firewall/Panorama: ")
    if args.username:
        user = args.username
    else:
        user = input("Enter the user login: ")
    if args.password:
        pw = args.password
    else:
        pw = getpass.getpass()

except KeyboardInterrupt:
    print('\n')
    print("Keyboard interrupt.  Exiting script.")
    raise SystemExit


class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open(LOG_FILE, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        # this flush method is needed for python 3 compatibility.
        # this handles the flush command by doing nothing.
        # you might want to specify some extra behavior here.
        pass


sys.stdout = Logger()


def keyboardinterrupthandler(signal):
    print('KeyboardInterrupt (ID: {}) has been caught. Exiting script'.format(signal))
    exit(0)


def create_connection():

    mode = None
    try:
        device = base.PanDevice.create_from_device(ip, user, pw)
        if str(type(device)) == "<class 'pandevice.panorama.Panorama'>":
            mode = 'Panorama'
        if str(type(device)) == "<class 'pandevice.firewall.Firewall'>":
            mode = 'Firewall'
        print("Connected to " + mode)
        return device, mode
    except Exception:
        print('\n')
        print("There was a problem establishing a connection to the device.\n"
              "Check IP address/hostname/credentials and try again")
        print('\n')
        raise SystemExit


def get_api_output(device, mode):

    if mode == 'Panorama':

        output = device.op("<show><object><dynamic-address-group><all></all></dynamic-address-group></object></show>",
                           "vsys1", True, False)
        return etree.fromstring(output)


def get_devicegroups(dg_output):

    dg_list = []

    for entry in dg_output.findall("result/device-groups/entry"):
        dg_list.append(entry.attrib['name'])

    return dg_list


def get_dyn_group_members(dg_output):

    taggedobj = []
    with open('tagged_addresses_dynamic.csv', 'w', newline='') as output_file:
        output_writer = csv.writer(output_file, delimiter=',')
        for entry in dg_output.findall("result/device-groups/entry"):
            for addrgrp in entry:
                dg_name = addrgrp.attrib['name']
                for y in addrgrp.findall('member-list'):
                    for x in y:
                        output_writer.writerow([dg_name, x.attrib['name']])
                        taggedobj.append(x.attrib['name'])
        return taggedobj


def get_address_objects(device, dg_list, group_members):

    i = 0

    with open('tagged_addresses_not_dynamic.csv', 'w', newline='') as output_file:
        output_writer = csv.writer(output_file, delimiter=',')
        for dg in dg_list:
            pano = device.add(panorama.DeviceGroup(dg))
            objects.AddressObject.refreshall(pano, add=True)

            for addrobject in pano.children:
                if addrobject.tag:
                    if addrobject.name not in group_members:
                        i += 1
                        output_writer.writerow([str(dg), str(addrobject), str(addrobject.tag)])
                        print('tagged - ' + str(dg) + ' - ' + str(addrobject) + ' - ' + str(addrobject.tag))
    print('\n')
    print('Total tagged addresses: ' + str(i))


def main():

    signal.signal(signal.SIGINT, keyboardinterrupthandler)
    device, mode = create_connection()
    dg_output = get_api_output(device, mode)
    dg_list = get_devicegroups(dg_output)
    groups_members = get_dyn_group_members(dg_output)
    get_address_objects(device, dg_list, groups_members)


if __name__ == '__main__':

    if len(sys.argv) > 5:
        print(__doc__)
    else:
        main()
