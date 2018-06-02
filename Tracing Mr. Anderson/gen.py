import random
from scapy.all import Ether, IP, UDP, Raw
from scapy.utils import PcapWriter


srand=random.SystemRandom()
ids = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPRSTUVWXYZ_0123456789"

def gen_ip():
    return '.'.join([str(srand.randint(1,223))]+[str(srand.randint(0,255)) for _ in range(3)])

via_tpl = "Via: SIP/2.0/UDP %s:%s;branch=%s\r\n"

def gen_vias(d1):
    vs = [(
        gen_ip(),
        str(srand.randint(10000,65000)),
        ''.join(srand.choice(ids) for _ in range(32)),
        ) for _ in range(srand.randint(0,16))]
    vs = [(d1['sip'],d1['vport'],''.join(srand.choice(ids) for _ in range(32)),)]+vs
    return "".join(via_tpl % i for i in vs)

sdp_tpl = """v=0\r
o=sip:{sphone}@{sip} 1 16 IN IP4 {sip}\r
s=sip:{sphone}@{sip}\r
c=IN IP4 {sip}\r
t=0 0\r
m=audio {sport} RTP/AVP 0\r
a=rtpmap:0 PCMU/8000/1\r
"""

def gen_sdp(d1):
    return sdp_tpl.format(**d1)

def gen_invite_dict():
    d1 = {
        'dphone': ''.join(str(srand.randint(0,9)) for _ in range(15)),
        'sphone': ''.join(str(srand.randint(0,9)) for _ in range(15)),
        'sip': gen_ip(),
        'dip': gen_ip(),
        'callid': ''.join(srand.choice(ids) for _ in range(32)),
        'cseq': str(srand.randint(0,4096)),
        'sbid': ''.join(srand.choice(ids) for _ in range(32)),
        'maxfwds': str(srand.randint(10,100)),
        'useragent': 'Phone%d%015d' % (srand.randint(1,9),srand.randint(0,999999999999999)),
        'sport': str(srand.randint(10000,65000)),
        'vport': str(srand.randint(10000,65000))
    }
    d1['vias'] = gen_vias(d1)
    d1['sdp'] = gen_sdp(d1)
    d1['sdplen'] = len(d1['sdp'])
    return d1
        

inv_tpl = """INVITE sip:{dphone}@{dip} SIP/2.0\r
From: sip:{sphone}@{sip}\r
To: sip:{dphone}@{dip}\r
Call-ID: {callid}@{sip}\r
Cseq: {cseq} INVITE\r
{vias}Content-Length: {sdplen}
Max-Forwards: {maxfwds}
Contact: sip:{sphone}@{sip};transport=udp\r
Content-Type: application/sdp
User-Agent: {useragent}\r
\r
{sdp}"""

def gen_invite(d):
    return inv_tpl.format(**d)

def gen_pkt(d):
    return (  Ether(src=':'.join("%02x" % (srand.randint(0,255),) for _ in range(6)),
                  dst=':'.join("%02x" % (srand.randint(0,255),) for _ in range(6)))
            / IP(src=d['sip'],
               dst=gen_ip())
            / UDP(sport=int(d['vport']),
                dport=srand.randint(10000,65000))
            / Raw(load=gen_invite(d)))

with PcapWriter("trace.pcap", append=False, sync=True) as pktdump:
    special = srand.randint(250000,750000)
    print("Special is: ",special)
    for i in range(0,special):
        pktdump.write(gen_pkt(gen_invite_dict()))
        if i % 1000 == 0 :
            print (i)
    d = gen_invite_dict()
    d['useragent'] = 'Phone0%015d' % (srand.randint(0,999999999999999,))
    pktdump.write(gen_pkt(d))
    for i in range(special+1,1000000):
        pktdump.write(gen_pkt(gen_invite_dict()))
        if i % 1000 == 0 :
            print (i)
