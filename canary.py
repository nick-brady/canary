import time
from datetime import timedelta
from pprint import pprint
import requests

from scapy.all import sniff, Dot11ProbeReq

seen_devices = {}
prog_start = time.time()

spotify_track_uri = 'spotify/now/spotify:track:'
zone = 'Kitchen'
people = {
    'B2:ED:4B:6B:C1:33': {
        'name': 'Nick Brady',
        'track_id': '63l4zrmZPCAq4n2U0T1KII'
    },
    'F0:C3:71:29:69:C6': {
        'name': 'Alexis Pearce',
        'track_id': '58jecLK0epwMLr9cy5vFUy'
    },
    'DC:52:85:DF:7A:80': {
        'name': 'Paul Pearce',
        'track_id': '7jman10UPhzhtOOqZLjSsh'
    }
}

def print_statuses(now):
    for mac, person in people.items():
        try:
            person_last_seen = now - seen_devices[mac]
            hours, remainder = divmod(person_last_seen, 3600)
            minutes, seconds = divmod(remainder, 60)
            last_seen_str = '{:02}:{:02}:{:02}'.format(int(hours), int(minutes), int(seconds))
            print(person['name'] + ' time since seen: ' + last_seen_str)
        except KeyError:
            print(person['name'] + ' has not been seen!')
    print('----')

def handle_packet(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return
    if pkt.type == 0 and pkt.subtype == 4:
        mac = pkt.addr2.upper()
        now = time.time()
        try:
            last_seen = timedelta(
                seconds=now - seen_devices[mac]
            )
            time_since_start = timedelta(seconds=now - prog_start)
            seen_devices[mac] = now
            if people.get(mac, False) and \
                    last_seen > timedelta(minutes=5) and \
                    time_since_start > timedelta(minutes=2): #give time for devices to populate
                # play music, someone's home!
                person = people[mac]
                print(person['name'] + ' is home! lets hear it!')
                # time.sleep(60)
                requests.get('http://127.0.0.1:5005/'+zone+'/'+spotify_track_uri+person['track_id'])
                # http://192.168.86.89:5005/Kitchen/pause
        except KeyError:
            seen_devices[mac] = now
            last_seen = None

        print_statuses(now)


def main():
    sniff(iface='wlan1', prn=handle_packet)

if __name__ == '__main__':
    main()
