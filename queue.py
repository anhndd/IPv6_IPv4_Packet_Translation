#!/usr/bin/python
# coding=utf-8
import nfqueue, socket, sys
from scapy.all import *

MAC_client = "22:f6:7f:c9:0c:28"
MAC_server = "b2:74:40:99:3e:eb"
# MAC_server = "52:54:00:12:35:02" # not important
ipv6_server = "2001:2:3:4501:b074:40ff:fe99:3eeb"
ipv4_server = "10.189.139.68"
ipv4_client = "10.0.2.15"

hmap_save = {}

isFirst = int(sys.argv[1])


def traite_paquet(number, payload):
    global hmap_save
    global isFirst

    print("number", number)
    # le paquet est fourni sous forme d'une séquence d'octet, il faut l'importer
    data = payload.get_data()

    # il faut identifier sa nature IPv6 ou IPv4
    premier_quartet = data[0].encode("hex")[0]
    if (premier_quartet == '4'):
        # paquet IPv4
        pkt = IP(data)

        if not isFirst:
            if (ipv4_client, pkt["TCP"].dport) in hmap_save:
                ipv6_client = hmap_save[(ipv4_client, pkt["TCP"].dport)]

                layers = pkt.layers()

                new_pkt = Ether(dst=MAC_client, src=MAC_server, type=0x86dd) / IPv6(src=ipv6_server, dst=ipv6_client) / TCP(
                    sport=pkt["TCP"].sport, dport=pkt["TCP"].dport, flags=pkt["TCP"].flags,
                    seq=pkt["TCP"].seq, ack=pkt["TCP"].ack, dataofs=pkt["TCP"].dataofs,
                    reserved=pkt["TCP"].reserved, window=pkt["TCP"].window,
                    urgptr=pkt["TCP"].urgptr, options=pkt["TCP"].options)

                for i in range(2, len(layers)):
                    new_pkt = new_pkt / pkt[layers[i]]

                # new_pkt = Ether(dst=MAC_client, src=MAC_server, type=0x86dd) / IPv6(src=ipv6_server, dst=ipv6_client)
                # for i in range(1, len(layers)):
                #     new_pkt = new_pkt / pkt[layers[i]]
                # del new_pkt['TCP'].chksum

                sendp(new_pkt, iface="switchipv6")
                payload.set_verdict(nfqueue.NF_DROP)
                print("change IPv4 -> IPv6")
            else:
                payload.set_verdict(nfqueue.NF_ACCEPT)
        else:
            payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        # paquet IPv6
        pkt = IPv6(data)

        print(isFirst)
        if not isFirst:
            hmap_save[(ipv4_client, pkt["TCP"].sport)] = pkt.src

            layers = pkt.layers()

            new_pkt = IP(src=ipv4_client, dst=ipv4_server) / TCP(sport=pkt["TCP"].sport, dport=pkt["TCP"].dport,
                                                                 flags=pkt["TCP"].flags, seq=pkt["TCP"].seq,
                                                                 ack=pkt["TCP"].ack, dataofs=pkt["TCP"].dataofs,
                                                                 reserved=pkt["TCP"].reserved, window=pkt["TCP"].window,
                                                                 urgptr=pkt["TCP"].urgptr, options=pkt["TCP"].options)

            for i in range(2, len(layers)):
                new_pkt = new_pkt / pkt[layers[i]]

            # new_pkt = IP(src=ipv4_client, dst=ipv4_server)
            # for i in range(1, len(layers)):
            #     new_pkt = new_pkt / pkt[layers[i]]
            # del new_pkt['TCP'].chksum

            send(new_pkt)

            payload.set_verdict(nfqueue.NF_DROP)
            print("change IPv6 -> IPv4")
        else:
            payload.set_verdict(nfqueue.NF_ACCEPT)


# accepte le paquet : le paquet est remis dans la pile TCP/IP et poursuit sa route
# payload.set_verdict(nfqueue.NF_ACCEPT)
# si modifie : le paquet est remis MODIFIE dans la pile TCP/IP et poursuit sa route
# payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
# si rejete : le paquet est rejeté
# payload.set_verdict(nfqueue.NF_DROP)
q = nfqueue.queue()
q.open()
q.unbind(socket.AF_INET6)
q.unbind(socket.AF_INET)
q.bind(socket.AF_INET6)
q.bind(socket.AF_INET)
q.set_callback(traite_paquet)
q.create_queue(0)
try:
    q.try_run()
except KeyboardInterrupt as e:
    print("interruption")
q.unbind(socket.AF_INET)
q.unbind(socket.AF_INET6)
q.close()
