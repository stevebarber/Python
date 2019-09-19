#!/usr/bin/env python

"""
pan_zone_split.py
==========================

Break out firewall rules where there are multiple zones for both source and destination.

-i, --ip, help="Name or IP address of the firewall/Panorama"
-u, --username, help="User login"
-p, --password, help="Login password"

"""
try:
    import sys
    import os
    import signal
    import getpass
    import argparse
    import datetime

    from pandevice import panorama, policies
    from copy import deepcopy
    from variables import *
except ImportError:
    raise ImportError('Verify the proper python modules are installed')

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help="Name or IP address of the firewall/Panorama")
parser.add_argument("-u", "--username", help="User login")
parser.add_argument("-p", "--password", help="Login password")
args = parser.parse_args()

i = 0

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
    print('Keyboard interrupt.  Exiting script.')
    try:
        exit()
    except SystemExit:
        os._exit()


class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open(LOG_FILE +'_'+ datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + '.log', 'a')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        # this flush method is needed for python 3 compatibility.
        # this handles the flush command by doing nothing.
        # you might want to specify some extra behavior here.
        pass


sys.stdout = Logger()


def keyboardInterruptHandler(signal, frame):
    print('KeyboardInterrupt (ID: {}) has been caught. Exiting script'.format(signal))
    exit(0)


def rule_clone(rule, pano, postrulebase):

    global i

    print('Rule name: {0} - From zone: {1} - To zone: {2}'.format(rule.name, rule.fromzone, rule.tozone))
    i += 1
    n = 0
    for srczone in rule.fromzone:
        for dstzone in rule.tozone:
            if dstzone != srczone:
                n += 1
                print('   ---   from: ' + srczone + ' to: ' + dstzone + ' rule#: ' + str(n))
                rule_copy = postrulebase.add(deepcopy(rule))
                rule_copy.name = rule.name + RULE_SUFFIX + str(n)
                rule_copy.fromzone = None
                rule_copy.tozone = None
                rule_copy.fromzone = srczone
                rule_copy.tozone = dstzone
                if rule_copy.tag == None:
                    rule_copy.tag = RULE_TAG
                elif not RULE_TAG in rule_copy.tag:
                    rule_copy.tag.append(RULE_TAG)
                rule_copy.create()
                pano.xapi.move(rule_copy.xpath(), 'before', rule.name)
    if rule.tag == None:
        rule.tag = RULE_TAG
    elif not RULE_TAG in rule.tag:
        rule.tag.append(RULE_TAG)
    rule.apply()


def main():

    signal.signal(signal.SIGINT, keyboardInterruptHandler)

    try:
        pano = panorama.Panorama(ip, user, pw)

        dg = panorama.DeviceGroup(DEVICE_GROUP)
        pano.add(dg)

        postrulebase = policies.PostRulebase()
        dg.add(postrulebase)

        rule_refresh = policies.SecurityRule.refreshall(postrulebase)

        rule_list = postrulebase.children

        for rule in rule_list:
            if SPLIT_DISABLED or (not SPLIT_DISABLED and not rule.disabled):
                if len(rule.fromzone) > 1 and len(rule.tozone) > 1:
                    if rule.tag == None or not RULE_TAG in rule.tag:
                        rule_clone(rule, pano, postrulebase)

        print('')
        print('Total source rules cloned: ' + str(i))

    except Exception as e:
        print(e)
        print('Error.  Verify credentials/device address/device group name and try again.')
        exit(0)


if __name__ == '__main__':

    if len(sys.argv) > 5:
        print(__doc__)
    else:
        main()
