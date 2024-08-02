#!/usr/bin/env python3

#
# Copyright 2019 me@sigsec.net
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# Code for article:
# https://blog.sigsec.net/posts/2019/04/reading-and-writing-nfc-tags.html
#
# You'll need to use my fork of nfcpy for Python 3, found here:
# https://github.com/sigsec/nfcpy

from time import sleep

import nfc
import ndef
from nfc.clf import RemoteTarget


#
# Main function, for when this file is run as a script
#

def write_text(tag):
    record = ndef.TextRecord("Hello sigsec readers!")
    tag.ndef.records = [record]

def write_wifi(tag):
    credential = ndef.wifi.Credential()
    credential.set_attribute('ssid', b'MyNetworkSSID')
    credential.set_attribute('authentication-type', 'WPA2-Personal')
    credential.set_attribute('encryption-type', 'AES')
    credential.set_attribute('network-key', b'WiFi-Pa$$w0rd')
    credential.set_attribute('mac-address', bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))

    record = ndef.WifiSimpleConfigRecord()
    record.set_attribute('credential', credential)
    record.set_attribute('rf-bands', ('2.4GHz', '5.0GHz'))

    tag.ndef.records = [record]

def write_url(tag):
    record = ndef.UriRecord("https://www.example.org/")
    tag.ndef.records = [record]

def main():
    with nfc.ContactlessFrontend('usb:072f:2200') as clf:
        while True:
            target = clf.sense(RemoteTarget('106A'))

            if target is None:
                sleep(0.1)  # don't burn the CPU
                continue

            serial = target.sdd_res.hex()
            print("Found a target with serial " + serial + "!")

            tag = nfc.tag.activate(clf, target)

            if tag.ndef:
                print("Tag is NDEF formatted!")
                print("It has " + str(len(tag.ndef.records)) + " records.")
                for record in tag.ndef.records:
                    print("    Record: " + record)

                # To write a record to the tag, uncomment one of these lines:
                # write_text(tag)
                # write_wifi(tag)
                # write_url(tag)

            else:
                print("Tag is not NDEF formatted.")
                # We can still read and write raw memory on the chip.
                # using `tag.read(page)` and `tag.write(page, data)`

            print("Sleeping for 5 seconds before reading the next tag...")
            sleep(5)


if __name__ == '__main__':
    main()
