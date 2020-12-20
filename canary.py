import time
from datetime import timedelta
from pprint import pprint

from scapy.all import sniff, Dot11ProbeReq

seen_devices = {}

def handle_packet(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return
    if pkt.type == 0 and pkt.subtype == 4:
        mac = pkt.addr2.upper()
        now = time.time()
        try:
            last_seen = timedelta(
                seconds=seen_devices[mac] - now
            )
            seen_devices[mac] = now
            # if last_seen > timedelta(hours=1):
                # play music, someone's home!
        except KeyError:
            seen_devices[mac] = now

        pprint(seen_devices)

def main():
    sniff(iface='wlan1', prn=handle_packet)

if __name__ == '__main__':
    main()
