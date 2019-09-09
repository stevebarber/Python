#!/usr/bin/env python

"""
pan-wildfire-query.py
==========================

Submit hashes to WildFire and return verdict
Read list of hashes from txt file defined in variables.py

"""
try:
    import sys
    import io
    import datetime
    import signal
    import urllib
    import urllib.request
    from urllib.parse import urlencode, quote_plus
    import ssl
    from xml.dom import minidom
    from variables import *
except ImportError:
    raise ImportError('Verify the proper python modules are installed')

i_malware = 0
i_benign = 0
i_hash_error = 0

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
    print('')
    print('---------- Totals ----------')
    print(' - malicious hashes: ' + str(i_malware))
    print(' - benign hashes: ' + str(i_benign))
    print(' - hash errors: ' + str(i_hash_error))
    print(' - hashes submitted: ' + str(i_malware + i_benign))
    exit(0)


def read_file():

    try:
        print('Reading hashes...')
        print('Connecting to WildFire API...')
        print('')
        with io.open(HASH_FILE, 'r') as fileHandler:
            for line in fileHandler:
                if not line == '\n' or line == '':
                    query_wf(line.rstrip())
    except IOError:
        print('Error opening hashes file.')


def query_wf(wf_hash):

    global i_malware, i_benign, i_hash_error

    try:
        context = ssl._create_unverified_context()
        url = 'https://wildfire.paloaltonetworks.com/publicapi/get/report'
        values = {'apikey': API_KEY, 'hash': wf_hash}
        parsedKey = send_api_request(url, values)
        nodes = parsedKey.getElementsByTagName('malware')
        key = nodes[0].firstChild.nodeValue

        if key == 'yes':
            i_malware += 1
            print(wf_hash + ' : malware')
        else:
            i_benign += 1
            print(wf_hash + ' : benign')
    except Exception as e:
        i_hash_error += 1
        print('There was a problem submitting hash (' + wf_hash + ') WildFire.  Verify API key or hashes and try again.')
        pass


def send_api_request(url, values):
    # Function to send the api request to WildFire and return the
    # parsed response.
    try:
        data = urlencode(values, quote_via=quote_plus).encode('utf-8')
        request = urllib.request.Request(url, data)
        response = urllib.request.urlopen(request)
        return minidom.parse(response)
    except Exception:
        print('There was an error trying to access the WildFire site.  Check network settings and try again')
        exit(0)


def main():

    signal.signal(signal.SIGINT, keyboardInterruptHandler)

    print('')
    read_file()
    print('')
    print('---------- Totals ----------')
    print(' - malicious hashes: ' + str(i_malware))
    print(' - benign hashes: ' + str(i_benign))
    print(' - hash errors: ' + str(i_hash_error))
    print(' - hashes submitted: ' + str(i_malware + i_benign))


if __name__ == '__main__':

    if len(sys.argv) > 1:
        print(__doc__)
    else:
        main()


