from scapy.all import sniff, Dot11ProbeReq

def hp(pkt):
     global packet
     if not pkt.haslayer(Dot11ProbeReq):
         return
     print('is a probe!')
     packet = pkt
     if pkt.type == 0 and pkt.subtype == 4:
         print('FOUND ONE!')
         packet = pkt

def main():
    print('hello world')
    sniff(iface='en0', prn=hp)

if __name__ == '__main__':
    main()
