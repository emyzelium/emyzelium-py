"""
Emyzelium (Python)

is another wrapper around ZeroMQ's Publish-Subscribe messaging pattern
with mandatory Curve security and optional ZAP authentication filter,
over Tor, through Tor SOCKS proxy,
for distributed artificial elife, decision making etc. systems where
each peer, identified by its public key, onion address, and port,
publishes and updates vectors of vectors of bytes of data
under unique topics that other peers subscribe to
and receive the respective data.
 
https://github.com/emyzelium/emyzelium-py

emyzelium@protonmail.com
 
Copyright (c) 2022-2023 Emyzelium caretakers
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

"""
Source
"""

try:
	import zmq
except ImportError:
	print("Emyzelium requires \"PyZMQ\" package. Install e.g. by \"pip install [--user] pyzmq\"")
	exit(1)

from zmq.utils import z85

import secrets
import sys
import time


if (sys.version_info[0] < 3) or ((sys.version_info[0] == 3) and (sys.version_info[1] < 6)):
	print("Emyzelium requires Python 3.6 or later, found Python " + str(sys.version_info[0]) + "." + str(sys.version_info[1]))
	exit(1)


VERSION = "0.9.2"
DATE = "2023.10.11"

EW_OK = 0
EW_ALREADY_PRESENT = 1
EW_ALREADY_ABSENT = 2
EW_ALREADY_PAUSED = 3
EW_ALREADY_RESUMED = 4
EW_ABSENT = 5

KEY_Z85_LEN = 40

CURVE_MECHANISM_ID = b"CURVE" # See https://rfc.zeromq.org/spec/27/
ZAP_DOMAIN_ID = b"emyz"

ZAP_SESSION_ID_LEN = 32

DEF_IPV6_STATUS = 1
DEF_LINGER = 0

DEF_PUBSUB_PORT = 0xEDAF # 60847

DEF_TOR_PROXY_PORT = 9050 # default from /etc/tor/torrc
DEF_TOR_PROXY_HOST = "127.0.0.1" # default from /etc/tor/torrc


def time_musec(): # microseconds since Unix epoch
	if sys.version_info >= (3, 7):
		return time.time_ns() // 1000
	else:
		return round(time.time() * 1e6)


def cut_pad_key_str(s):
	return (s + (" " * (KEY_Z85_LEN - len(s)))) if len(s) < KEY_Z85_LEN else s[:KEY_Z85_LEN] 


class Etale:
	
	def __init__(self, parts=[], t_out=-1, t_in=-1, paused=False):
		self.parts = parts # list<bytes>
		self.t_out = t_out # int64, microsecs since Unix epoch
		self.t_in = t_in # int64, microsecs since Unix epoch
		self.paused = False


class Ehypha:

	def __init__(self, context, secretkey, publickey, serverkey, onion, pubsub_port, torproxy_port, torproxy_host):
		self.subsock = context.socket(zmq.SUB)
		self.subsock.set(zmq.LINGER, DEF_LINGER)
		self.subsock.curve_secretkey = secretkey.encode("ascii")
		self.subsock.curve_publickey = publickey.encode("ascii")
		self.subsock.curve_serverkey = serverkey.encode("ascii")

		self.subsock.set(zmq.SOCKS_PROXY, (f"{torproxy_host}:{torproxy_port}").encode("ascii"))
		
		self.subsock.connect(f"tcp://{onion}.onion:{pubsub_port}")

		self.etales = dict()


	def add_etale(self, title):
		if not (title in self.etales.keys()):
			topic = title.encode("utf8") + bytes([0])
			self.subsock.subscribe(topic)
			etale = Etale()
			self.etales[title] = etale
			return etale, EW_OK
		else:
			return self.etales[title], EW_ALREADY_PRESENT


	def get_etale(self, title):
		if title in self.etales.keys():
			return self.etales[title], EW_OK
		else:
			return None, EW_ABSENT


	def del_etale(self, title):
		if title in self.etales.keys():
			del self.etales[title]
			topic = title.encode("utf8") + bytes([0])
			self.subsock.unsubscribe(topic)
			return EW_OK
		else:
			return EW_ALREADY_ABSENT


	def pause_etale(self, title):
		if title in self.etales.keys():
			etale = self.etales[title]
			if not etale.paused:
				topic = title.encode("utf8") + bytes([0])
				self.subsock.unsubscribe(topic)
				etale.paused = True
				return EW_OK
			else:
				return EW_ALREADY_PAUSED
		else:
			return EW_ABSENT


	def resume_etale(self, title):
		if title in self.etales.keys():
			etale = self.etales[title]
			if etale.paused:
				topic = title.encode("utf8") + bytes([0])
				self.subsock.subscribe(topic)
				etale.paused = False
				return EW_OK
			else:
				return EW_ALREADY_RESUMED
		else:
			return EW_ABSENT


	def pause_etales(self):
		for title in self.etales.keys():
			self.pause_etale(title)


	def resume_etales(self):
		for title in self.etales.keys():
			self.resume_etale(title)


	def update(self):
		t = time_musec()

		while self.subsock.poll(0) > 0:
			message_parts = self.subsock.recv_multipart()
			# 0th is topic, 1st is remote time, rest (optional) is data
			if len(message_parts) >= 2:
				topic = message_parts[0]
				if len(topic) >= 1:
					title = topic[:-1].decode("utf8")
					if title in self.etales.keys():
						etale = self.etales[title]
						if not etale.paused:
							t_out_bytes = message_parts[1]
							if len(t_out_bytes) == 8:
								etale.parts = message_parts[2:]
								etale.t_out = int.from_bytes(t_out_bytes, byteorder="little")
								etale.t_in = t


class Efunguz:

	def __init__(self, secretkey, whitelist_publickeys=set(), pubsub_port=DEF_PUBSUB_PORT, torproxy_port=DEF_TOR_PROXY_PORT, torproxy_host=DEF_TOR_PROXY_HOST):
		self.context = zmq.Context()
		self.context.set(zmq.IPV6, DEF_IPV6_STATUS)

		self.secretkey = cut_pad_key_str(secretkey)
		self.publickey = zmq.curve_public(self.secretkey.encode("ascii")).decode("ascii")

		self.whitelist_publickeys = set()
		for key in whitelist_publickeys:
			self.whitelist_publickeys.add(cut_pad_key_str(key))
		# if empty, allow all to subscribe; if non-empty, allow only those who have corresponding secretkeys

		self.pubsub_port = pubsub_port

		self.torproxy_port = torproxy_port
		self.torproxy_host = torproxy_host

		self.ehyphae = dict()

		# At first, REP socket for ZAP auth...
		self.zapsock = self.context.socket(zmq.REP)
		self.zapsock.set(zmq.LINGER, DEF_LINGER)
		self.zapsock.bind("inproc://zeromq.zap.01")

		self.zap_session_id = secrets.token_bytes(ZAP_SESSION_ID_LEN) # must be cryptographically random... is it?

		# ..and only then, PUB socket
		self.pubsock = self.context.socket(zmq.PUB)
		self.pubsock.set(zmq.LINGER, DEF_LINGER)
		self.pubsock.curve_server = True
		self.pubsock.curve_secretkey = self.secretkey.encode("ascii")
		self.pubsock.set(zmq.ZAP_DOMAIN, ZAP_DOMAIN_ID) # to enable auth, must be non-empty due to ZMQ RFC 27
		self.pubsock.set(zmq.ROUTING_ID, self.zap_session_id) # to make sure only this pubsock can pass auth through zapsock; see update()
		self.pubsock.bind(f"tcp://*:{self.pubsub_port}")


	def add_whitelist_publickeys(self, publickeys):
		for key in publickeys:
			self.whitelist_publickeys.add(cut_pad_key_str(key))


	def del_whitelist_publickeys(self, publickeys):
		for key in publickeys:
			self.whitelist_publickeys.discard(cut_pad_key_str(key))


	def clear_whitelist_publickeys(self):
		self.whitelist_publickeys.clear()


	def read_whitelist_publickeys(self, filepath):
		lines = open(filepath).readlines()
		for line in lines:
			line = line[:-1] # remove "\n" at the end
			if len(line) >= KEY_Z85_LEN:
				key = line[:KEY_Z85_LEN]
				self.whitelist_publickeys.add(key)


	def add_ehypha(self, that_publickey, onion, pubsub_port=DEF_PUBSUB_PORT):
		serverkey = cut_pad_key_str(that_publickey)
		if not (serverkey in self.ehyphae.keys()):
			ehypha = Ehypha(self.context, self.secretkey, self.publickey, serverkey, onion, pubsub_port, self.torproxy_port, self.torproxy_host)
			self.ehyphae[serverkey] = ehypha
			return ehypha, EW_OK
		else:
			return self.ehyphae[serverkey], EW_ALREADY_PRESENT


	def get_ehypha(self, publickey):
		cp_publickey = cut_pad_key_str(publickey)
		if cp_publickey in self.ehyphae.keys():
			return self.ehyphae[cp_publickey], EW_OK
		else:
			return None, EW_ABSENT


	def del_ehypha(self, that_publickey):
		serverkey = cut_pad_key_str(that_publickey)
		if serverkey in self.ehyphae.keys():
			del self.ehyphae[serverkey]
			return EW_OK
		else:
			return EW_ALREADY_ABSENT


	def emit_etale(self, title, parts):
		topic = title.encode("utf8") + bytes([0])
		t_out = time_musec()
		t_out_bytes = t_out.to_bytes(8, byteorder="little")
		self.pubsock.send_multipart([topic] + [t_out_bytes] + parts)


	def update(self):
		while self.zapsock.poll(0) > 0:
			msg_parts = self.zapsock.recv_multipart()
			version, sequence, domain, address, identity, mechanism, key = msg_parts[:7]
			key_b = z85.encode(key)
			key_s = key_b.decode("ascii")
			reply = [version, sequence]
			if (identity == self.zap_session_id) and (mechanism == CURVE_MECHANISM_ID) and ((len(self.whitelist_publickeys) == 0) or (key_s in self.whitelist_publickeys)):
				reply += [b"200", b"OK", key_b, b""] # Auth passed
			else:
				reply += [b"400", b"FAILED", b"", b""] # Auth failed
			self.zapsock.send_multipart(reply)

		for eh in self.ehyphae.values():
			eh.update()
