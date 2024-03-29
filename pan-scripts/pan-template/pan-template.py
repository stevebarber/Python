#!/usr/bin/env python

"""
pan-template.py
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

from pandevice import base, device, panorama, network, objects, firewall, policies
from netaddr import *
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


class logger(object):
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


sys.stdout = logger()


def keyboardInterruptHandler(signal, frame):
    print('KeyboardInterrupt (ID: {}) has been caught. Exiting script'.format(signal))
    exit(0)


def create_connection():

    mode = None
    try:
        device = base.PanDevice.create_from_device(ip, user, pw)
        if str(type(device)) == "<class 'pandevice.panorama.Panorama'>":
            mode = 'Panorama'
        if str(type(device)) == "<class 'pandevice.firewall.Firewall'>":
            mode =  "Firewall"
        return device, mode
    except:
        print('\n')
        print("There was a problem establishing a connection to the device.\n" \
              "Check IP address/hostname/credentials and try again")
        print('\n')
        raise SystemExit


def main():

    signal.signal(signal.SIGINT, keyboardInterruptHandler)

    device, mode = create_connection()
    print("Connected to " + mode)


if __name__ == '__main__':

    if len(sys.argv) > 5:
        print(__doc__)
    else:
        main()
