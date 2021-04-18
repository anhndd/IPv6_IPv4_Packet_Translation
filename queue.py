#!/usr/bin/python
# coding=utf-8
import nfqueue, socket
from scapy.all import *
def traite_paquet(payload):
	# le paquet est fourni sous forme d'une séquence d'octet, il faut l'importer
	data = payload.get_data()
	# il faut identifier sa nature IPv6 ou IPv4
	premier_quartet = data[0].encode("hex")[0]
	if (premier_quartet == '4') :
		# paquet IPv4
		pkt = IP(data)
	else:
		# paquet IPv6
		pkt = IPv6(data)
	pkt.show()
	# accepte le paquet : le paquet est remis dans la pile TCP/IP et poursuit sa route
	#payload.set_verdict(nfqueue.NF_ACCEPT)
	# si modifie : le paquet est remis MODIFIE dans la pile TCP/IP et poursuit sa route
	#payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
	# si rejete : le paquet est rejeté
	#payload.set_verdict(nfqueue.NF_DROP)
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
