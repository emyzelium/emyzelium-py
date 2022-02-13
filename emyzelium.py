"""
Emyzelium (Python)

This is another gigathin wrapper around ZeroMQ's Publish-Subscribe and
Pipeline messaging patterns with mandatory Curve security and optional ZAP
authentication filter over TCP/IP for distributed artificial elife,
decision making etc. systems where each peer, identified by its public key,
provides and updates vectors of vectors of bytes under unique topics that
other peers can subscribe to and receive; peers obtain each other's
IP addresses:ports by sending beacons and subscribing to nameservers whose
addresses:ports are known.
 
https://github.com/emyzelium/emyzelium-py

emyzelium@protonmail.com
 
Copyright (c) 2022 Emyzelium caretakers
 
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

import sys
import time


if (sys.version_info[0] < 3) or ((sys.version_info[0] == 3) and (sys.version_info[1] < 6)):
	print("Emyzelium requires Python 3.6 or later, found Python " + str(sys.version_info[0]) + "." + str(sys.version_info[1]))
	exit(1)


VERSION = "0.7.2"
DATE = "2022.02.13"

EW_OK = 0
EW_ALREADY_PRESENT = 1
EW_ALREADY_ABSENT = 2
EW_ALREADY_PAUSED = 3
EW_ALREADY_RESUMED = 4
EW_ABSENT = 5

KEY_Z85_LEN = 40
KEY_Z85_CSTR_LEN = KEY_Z85_LEN + 1
KEY_BIN_LEN = 32

ROUTING_ID_PUBSUB = b"pubsub"
ROUTING_ID_BEACON = b"beacon"

DEF_IPV6_STATUS = 1

DEF_LINGER = 0

DEF_IP = "127.0.0.1"

DEF_EFUNGI_PUBSUB_PORT = 0xEDAF # 60847
DEF_ECATAL_BEACON_PORT = 0xCAEB # 51947
DEF_ECATAL_PUBSUB_PORT = 0xD21F # 53791

DEF_EFUNGI_ECATAL_FORGET_INTERVAL = round(60 * 1e6) # in microseconds
DEF_EFUNGI_BEACON_INTERVAL = round(2 * 1e6)

DEF_ECATAL_DEACTIVATE_INTERVAL = round(60 * 1e6)
DEF_ECATAL_PUBLISH_INTERVAL = round(1 * 1e6)
DEF_ECATAL_IDLE_INTERVAL = round(0.01 * 1e6)


def time_musec(): # microseconds since Unix epoch
	if sys.version_info >= (3, 7):
		return time.time_ns() // 1000
	else:
		return round(time.time() * 1e6)


def cut_pad_str(src, length, pad_ch=" "):
	dst = src[:length]
	dst += " " * max(0, length - len(src))
	return dst


class Etale:
	
	def __init__(self, parts=[], t_out=-1, t_in=-1, paused=False):
		self.parts = parts # list<bytes>
		self.t_out = t_out # int64, microsecs since Unix epoch
		self.t_in = t_in # int64, microsecs since Unix epoch
		self.paused = False


class Ehypha:

	def update_connpoint_via_ecatal(self, ecatal_publickey, connpoint, t):
		self.connpoints_via_ecatals[ecatal_publickey] = (connpoint, t)


	def remove_connpoint_via_ecatal(self, ecatal_publickey):
		if ecatal_publickey in self.connpoints_via_ecatals.keys():
			del self.connpoints_via_ecatals[ecatal_publickey]


	def set_connpoint(self, connpoint):
		if connpoint != self.connpoint:
			if self.connpoint != None:
				self.subsock.disconnect(self.connpoint)
			self.connpoint = connpoint
			if self.connpoint != None:
				self.subsock.connect(self.connpoint)


	def __init__(self, context, secretkey, publickey, serverkey, ecatal_forget_interval, connpoint=None):
		self.subsock = context.socket(zmq.SUB)
		self.subsock.set(zmq.LINGER, DEF_LINGER)
		self.subsock.curve_secretkey = secretkey.encode("ascii")
		self.subsock.curve_publickey = publickey.encode("ascii")
		self.subsock.curve_serverkey = serverkey.encode("ascii")
		self.ecatal_forget_interval = ecatal_forget_interval # if < 0, use connpoints from each ecatal indefinitely long; if >= 0, do not use after this time has passed since last update from given ecatal
		self.connpoint = None

		self.connpoints_via_ecatals = dict()

		self.set_connpoint(connpoint)

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

		connpoints_votes = dict()
		for cp, t_upd in self.connpoints_via_ecatals.values():
			if (self.ecatal_forget_interval < 0) or ((t - t_upd) <= self.ecatal_forget_interval):
				if cp in connpoints_votes.keys():
					connpoints_votes[cp] += 1
				else:
					connpoints_votes[cp] = 1

		if len(connpoints_votes) > 0:
			max_v, max_v_cp = 0, ""
			for cp, v in connpoints_votes.items():
				if v > max_v:
					max_v, max_v_cp = v, cp
			self.set_connpoint(max_v_cp)

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

	def __init__(self, secretkey, whitelist_publickeys=set(), pubsub_port=DEF_EFUNGI_PUBSUB_PORT, beacon_interval=DEF_EFUNGI_BEACON_INTERVAL, ecatal_forget_interval=DEF_EFUNGI_ECATAL_FORGET_INTERVAL):
		self.context = zmq.Context()
		self.context.set(zmq.IPV6, DEF_IPV6_STATUS)

		self.secretkey = cut_pad_str(secretkey, KEY_Z85_LEN)
		self.publickey = zmq.curve_public(self.secretkey.encode("ascii")).decode("ascii")

		self.whitelist_publickeys = set()
		for key in whitelist_publickeys:
			self.whitelist_publickeys.add(cut_pad_str(key, KEY_Z85_LEN))
		# if empty, allow all to subscribe; if non-empty, allow only those who have corresponding secretkeys

		self.pubsub_port = pubsub_port

		self.beacon_interval = beacon_interval
		self.t_last_beacon = 0

		self.ecatal_forget_interval = ecatal_forget_interval

		self.ehyphae = dict()

		self.zapsock = self.context.socket(zmq.REP)
		self.zapsock.set(zmq.LINGER, DEF_LINGER)
		self.zapsock.bind("inproc://zeromq.zap.01")

		self.pubsock = self.context.socket(zmq.PUB)
		self.pubsock.set(zmq.LINGER, DEF_LINGER)
		self.pubsock.curve_server = True
		self.pubsock.curve_secretkey = self.secretkey.encode("ascii")
		self.pubsock.set(zmq.ROUTING_ID, ROUTING_ID_PUBSUB)
		self.pubsock.bind(f"tcp://*:{self.pubsub_port}")

		self.ecatals_from = dict()
		self.ecatals_to = dict()


	def add_whitelist_publickeys(self, publickeys):
		for key in publickeys:
			self.whitelist_publickeys.add(cut_pad_str(key, KEY_Z85_LEN))


	def del_whitelist_publickeys(self, publickeys):
		for key in publickeys:
			self.whitelist_publickeys.discard(cut_pad_str(key, KEY_Z85_LEN))


	def add_ehypha(self, that_publickey, connpoint=None, ecatal_forget_interval=None):
		serverkey = cut_pad_str(that_publickey, KEY_Z85_LEN)
		if not (serverkey in self.ehyphae.keys()):
			if ecatal_forget_interval == None:
				ecatal_forget_interval = self.ecatal_forget_interval
			ehypha = Ehypha(self.context, self.secretkey, self.publickey, serverkey, ecatal_forget_interval, connpoint)
			self.ehyphae[serverkey] = ehypha
			for subsock in self.ecatals_from.values():
				subsock.subscribe(serverkey.encode("ascii"))
			return ehypha, EW_OK
		else:
			return self.ehyphae[serverkey], EW_ALREADY_PRESENT


	def del_ehypha(self, that_publickey):
		serverkey = cut_pad_str(that_publickey, KEY_Z85_LEN)
		if serverkey in self.ehyphae.keys():
			del self.ehyphae[serverkey]
			for subsock in self.ecatals_from.values():
				subsock.unsubscribe(serverkey.encode("ascii"))
			return EW_OK
		else:
			return EW_ALREADY_ABSENT


	def add_ecatal_from(self, that_publickey, connpoint):
		serverkey = cut_pad_str(that_publickey, KEY_Z85_LEN)
		if not (serverkey in self.ecatals_from.keys()):
			subsock = self.context.socket(zmq.SUB)
			subsock.set(zmq.LINGER, DEF_LINGER)
			subsock.curve_secretkey = self.secretkey.encode("ascii")
			subsock.curve_publickey = self.publickey.encode("ascii")
			subsock.curve_serverkey = serverkey.encode("ascii")
			for eh_key in self.ehyphae.keys():
				subsock.subscribe(eh_key.encode("ascii"))
			subsock.connect(connpoint)
			self.ecatals_from[serverkey] = subsock
			return EW_OK
		else:
			return EW_ALREADY_PRESENT


	def del_ecatal_from(self, that_publickey):
		serverkey = cut_pad_str(that_publickey, KEY_Z85_LEN)
		if serverkey in self.ecatals_from.keys():
			del self.ecatals_from[serverkey]
			for eh in self.ehyphae.values():
				eh.remove_connpoint_via_ecatal(serverkey)
			return EW_OK
		else:
			return EW_ALREADY_ABSENT


	def add_ecatal_to(self, that_publickey, connpoint):
		serverkey = cut_pad_str(that_publickey, KEY_Z85_LEN)
		if not (serverkey in self.ecatals_to.keys()):
			pushsock = self.context.socket(zmq.PUSH)
			pushsock.set(zmq.LINGER, DEF_LINGER)
			pushsock.set(zmq.CONFLATE, 1)
			pushsock.curve_secretkey = self.secretkey.encode("ascii")
			pushsock.curve_publickey = self.publickey.encode("ascii")
			pushsock.curve_serverkey = serverkey.encode("ascii")
			pushsock.connect(connpoint)
			self.ecatals_to[serverkey] = pushsock
			return EW_OK
		else:
			return EW_ALREADY_PRESENT


	def del_ecatal_to(self, that_publickey):
		serverkey = cut_pad_str(that_publickey, KEY_Z85_LEN)
		if serverkey in self.ecatals_to.keys():
			del self.ecatals_to[serverkey]
			return EW_OK
		else:
			return EW_ALREADY_ABSENT


	def emit_etale(self, title, parts):
		topic = title.encode("utf8") + bytes([0])
		t_out = time_musec()
		t_out_bytes = t_out.to_bytes(8, byteorder="little")
		self.pubsock.send_multipart([topic] + [t_out_bytes] + parts)


	def emit_beacon(self):
		pubsub_port_b = max(0, min(0xFFFF, self.pubsub_port)).to_bytes(2, byteorder="little")
		for pushsock in self.ecatals_to.values():
			pushsock.send(pubsub_port_b)


	def update(self):
		while self.zapsock.poll(0) > 0:
			msg_parts = self.zapsock.recv_multipart()
			version, sequence, domain, address, identity, mechanism, key = msg_parts[:7]
			key_b = z85.encode(key)
			key_s = key_b.decode("ascii")
			reply = [version, sequence]
			if (identity == ROUTING_ID_PUBSUB) and ((len(self.whitelist_publickeys) == 0) or (key_s in self.whitelist_publickeys)):
				reply += [b"200", b"OK", key_b, b""] # Auth passed
			else:
				reply += [b"400", b"FAILED", b"", b""] # Auth failed
			self.zapsock.send_multipart(reply)

		t = time_musec()

		if t - self.t_last_beacon >= self.beacon_interval:
			self.emit_beacon()
			self.t_last_beacon = t

		for ec_key, subsock in self.ecatals_from.items():
			while subsock.poll(0) > 0:
				msg_parts = subsock.recv_multipart()
				# 0th must be serverkey, 1st must be connpoint
				if len(msg_parts) == 2:
					# Sanity checks...
					try:
						that_publickey = msg_parts[0].decode("ascii") # fails if bytes of key chars are not in 0-127
						if len(that_publickey) == 40: # fails if key has wrong length
							if that_publickey in self.ehyphae.keys(): # fails if there is no ehypha with this key
								connpoint = msg_parts[1].decode("ascii") # fails if bytes of connpoint chars are not in 0-127
								if connpoint.startswith("tcp://"): # TODO: more sanity checks for connpoint ("ip:port", IPv4/IPv6 etc.)
									self.ehyphae[that_publickey].update_connpoint_via_ecatal(ec_key, connpoint, t)
					except UnicodeDecodeError:
						pass

		for eh in self.ehyphae.values():
			eh.update()


class Ecataloguz:

	def __init__(self, secretkey, beacon_whitelist_publickeys_with_comments=dict(), pubsub_whitelist_publickeys=set(), beacon_port=DEF_ECATAL_BEACON_PORT, pubsub_port=DEF_ECATAL_PUBSUB_PORT, deactivate_interval = DEF_ECATAL_DEACTIVATE_INTERVAL, publish_interval = DEF_ECATAL_PUBLISH_INTERVAL, idle_interval = DEF_ECATAL_IDLE_INTERVAL):
		self.secretkey = cut_pad_str(secretkey, KEY_Z85_LEN)

		self.publickey = zmq.curve_public(self.secretkey.encode("ascii")).decode("ascii")

		self.beacon_whitelist_publickeys = set()
		self.beacon_recs = dict()
		for skey, comment in beacon_whitelist_publickeys_with_comments.items():
			dkey = cut_pad_str(skey, KEY_Z85_LEN)
			self.beacon_whitelist_publickeys.add(dkey)
			self.beacon_recs[dkey] = ("", -1, comment) # connpoint (string), last time beacon was received (microsecs since Unix epoch), comment (string)
		# if empty, allow all to send beacons; if non-empty, allow only those who have corresponding secretkeys
		
		self.pubsub_whitelist_publickeys = set()
		for key in pubsub_whitelist_publickeys:
			self.pubsub_whitelist_publickeys.add(cut_pad_str(key, KEY_Z85_LEN))
		# if empty, allow all to subscribe; if non-empty, allow only those who have corresponding secretkeys

		self.beacon_port = beacon_port
		self.pubsub_port = pubsub_port

		self.deactivate_interval = deactivate_interval # if < 0, publish connpoint of each efunguz indefinitely long after last beacon; if >= 0, do not publish after this time has passed since last beacon from given efunguz
		self.publish_interval = publish_interval
		self.idle_interval = idle_interval

		self.context = zmq.Context()
		self.context.set(zmq.IPV6, DEF_IPV6_STATUS)

		self.zapsock = self.context.socket(zmq.REP)
		self.zapsock.set(zmq.LINGER, DEF_LINGER)
		self.zapsock.bind("inproc://zeromq.zap.01")
		
		self.pullsock = self.context.socket(zmq.PULL)
		self.pullsock.set(zmq.LINGER, DEF_LINGER)
		self.pullsock.curve_server = True
		self.pullsock.curve_secretkey = self.secretkey.encode("ascii")
		self.pullsock.set(zmq.ROUTING_ID, ROUTING_ID_BEACON)

		self.pubsock = self.context.socket(zmq.PUB)
		self.pubsock.set(zmq.LINGER, DEF_LINGER)
		self.pubsock.curve_server = True
		self.pubsock.curve_secretkey = self.secretkey.encode("ascii")
		self.pubsock.set(zmq.ROUTING_ID, ROUTING_ID_PUBSUB)


	def read_beacon_whitelist_publickeys_with_comments(self, filepath):
		lines = open(filepath).readlines()
		for line in lines:
			line = line[:-1] # remove "\n" at the end
			if len(line) >= KEY_Z85_LEN:
				key = line[:KEY_Z85_LEN]
				comment = line[(KEY_Z85_LEN + 1):] if (len(line) >= (KEY_Z85_LEN + 2)) else "" # " " or "\t" after key, then non-empty comment
				self.beacon_whitelist_publickeys.add(key)
				self.beacon_recs[key] = ("", -1, comment)


	def read_pubsub_whitelist_publickeys(self, filepath):
		lines = open(filepath).readlines()
		for line in lines:
			line = line[:-1] # remove "\n" at the end
			if len(line) >= KEY_Z85_LEN:
				key = line[:KEY_Z85_LEN]
				self.pubsub_whitelist_publickeys.add(key)


	def run(self, tui=True):
		def add_attrstrs_to_termscr(termscr, attrstrs):
			for attrstr in attrstrs:
				if len(attrstr) == 1:
					termscr.addstr(attrstr[0])
				elif len(attrstr) == 2:
					termscr.addstr(attrstr[0], attrstr[1])

		# TODO: Externalize TUI ?

		def run(termscr):
			# Init TUI
			if termscr != None:
				termscr.nodelay(True)
				curses.curs_set(0)
				if curses.can_change_color():
					curses.init_color(0, 0, 0, 0)

				show_active_now = True
				show_comments = True
				i_page = 0
				page_size = max(1, curses.LINES - 11)

				t_start = time_musec()

			t_last_pub = 0

			while True:
				while self.zapsock.poll(0) > 0:
					msg_parts = self.zapsock.recv_multipart()
					version, sequence, domain, address, identity, mechanism, key = msg_parts[:7]
					key_b = z85.encode(key)
					key_s = key_b.decode("ascii")
					reply = [version, sequence]
					if ((identity == ROUTING_ID_BEACON) and ((len(self.beacon_whitelist_publickeys) == 0) or (key_s in self.beacon_whitelist_publickeys))) or ((identity == ROUTING_ID_PUBSUB) and ((len(self.pubsub_whitelist_publickeys) == 0) or (key_s in self.pubsub_whitelist_publickeys))):
						reply += [b"200", b"OK", key_b, b""] # Auth passed, set user-id to client's publickey
					else:
						reply += [b"400", b"FAILED", b"", b""] # Auth failed
					self.zapsock.send_multipart(reply)

				t = time_musec()

				idle_interval = self.idle_interval // 1000
				while self.pullsock.poll(idle_interval) > 0:
					idle_interval = 0
					# Auth passed
					frame = self.pullsock.recv(copy=False) # Frame instead of message to obtain metadata (peer-address etc.)
					if len(frame.bytes) == 2:
						key = frame.get("User-Id") # string, not bytes
						ip = frame.get("Peer-Address")
						port = int.from_bytes(frame.bytes, byteorder="little")
						connpoint = f"tcp://{ip}:{port}"
						if key in self.beacon_recs.keys():
							_, _, comment = self.beacon_recs[key]
							self.beacon_recs[key] = (connpoint, t, comment)
						else:
							self.beacon_recs[key] = (connpoint, t, "")

				if t - t_last_pub > self.publish_interval:
					for key, (connpoint, t_last_beac, comment) in self.beacon_recs.items():
						if (self.deactivate_interval >= 0) and (t - t_last_beac > self.deactivate_interval):
							connpoint = ""
							self.beacon_recs[key] = (connpoint, t_last_beac, comment)
						if connpoint != "":
							self.pubsock.send_multipart([key.encode("ascii"), connpoint.encode("ascii")])
					t_last_pub = t
				
				# Show TUI and process input
				if termscr != None:
					termscr.erase()
					termscr.addstr(0, 0, f"ecataloguz of Emyzelium v{VERSION} ({DATE})\n", curses.A_REVERSE | curses.A_BOLD)
					since_start_str_begin = "Since start: "
					since_start_str_end = f"{(t - t_start) // 1000000}"
					termscr.addstr(0, curses.COLS - len(since_start_str_begin) - len(since_start_str_end), since_start_str_begin)
					termscr.addstr(since_start_str_end, curses.A_BOLD)
					termscr.addstr(1, 0, "Public key (Z85) ")
					add_attrstrs_to_termscr(termscr, [
						[self.publickey + "\n", curses.A_BOLD],
						["Ports: beacon "], [f"{self.beacon_port}", curses.A_BOLD],
						[", pubsub "], [f"{self.pubsub_port}\n", curses.A_BOLD],
						["Intervals: deactivate "], [f"{(self.deactivate_interval * 1e-6):.1f}", curses.A_BOLD],
						[", publish "], [f"{(self.publish_interval * 1e-6):.1f}", curses.A_BOLD],
						[", sleep "], [f"{(self.idle_interval * 1e-6):.1f}\n", curses.A_BOLD]
					])
					termscr.addstr(5, 0, "-" * 112)
					termscr.addstr(5, 2, ("[ Active now" if show_active_now else "[ Active once") + f": page {i_page + 1} ]")
					try:
						termscr.addstr(6, 0, "COMMENT" if show_comments else "PUBLIC KEY")
						termscr.addstr(6, 44, "CONNPOINT")
						termscr.addstr(6, 92, "SINCE LAST BEACON")

						n_active_now = 0
						n_active_once = 0
						for key, (connpoint, t_last_beac, comment) in self.beacon_recs.items():
							if t_last_beac >= 0:
								n_active_once += 1
								if connpoint != "":
									n_active_now += 1
								j = n_active_now if show_active_now else n_active_once
								j -= i_page * page_size
								if (j > 0) and (j <= page_size) and ((not show_active_now) or (connpoint != "")):
									termscr.addstr(6 + j, 0, comment[:KEY_Z85_LEN] if show_comments else key, curses.A_BOLD)
									termscr.addstr(6 + j, 44, connpoint[:48], curses.A_BOLD)
									termscr.addstr(6 + j, 92, f"{((t - t_last_beac) * 1e-6):.1f}"[:16], curses.A_BOLD)

						termscr.addstr(7 + page_size, 0, "-" * 112)
						termscr.addstr(8 + page_size, 0, "Pages: [PageUp] previous, [PageDown] next, [Home] 1st, [End] last")
						termscr.addstr(4, 0, f"Efungi: ")
						add_attrstrs_to_termscr(termscr, [
							["beacon - whitelisted "],
							[f"{len(self.beacon_whitelist_publickeys)}", curses.A_BOLD],
							[", active once "],
							[f"{n_active_once}", curses.A_BOLD],
							[", active now "],
							[f"{n_active_now}", curses.A_BOLD],
							["; pubsub - whitelisted "],
							[f"{len(self.pubsub_whitelist_publickeys)}", curses.A_BOLD]
						])
					except curses.error: # if some starting position is outside of window
						pass
					termscr.addstr(curses.LINES - 1, 0, "[Q] quit, [A] show active now/once, [C] show comments/keys")
					
					termscr.refresh()

					ch = termscr.getch()

					if ch in [ord('q'), ord('Q')]:
						break
					elif ch in [ord('a'), ord('A')]:
						show_active_now = not show_active_now
					elif ch in [ord('c'), ord('C')]:
						show_comments = not show_comments
					elif (ch == curses.KEY_PPAGE) and (i_page > 0):
						i_page -= 1
					elif (ch == curses.KEY_NPAGE):
						i_page += 1
					elif (ch == curses.KEY_HOME):
						i_page = 0
					elif (ch == curses.KEY_END):
						i_page = max(0, (n_active_now if show_active_now else n_active_once) - 1) // page_size

		self.pullsock.bind(f"tcp://*:{self.beacon_port}")
		self.pubsock.bind(f"tcp://*:{self.pubsub_port}")

		if tui:
			try:
				import curses
			except ImportError:
				print("TUI of Emyzelium's Ecataloguz requires \"curses\" package.\nOn Windows, install \"windows-curses\" package e.g. by \"pip install [--user] windows-curses\"")
				exit(1)				
			curses.wrapper(run)
		else:
			run(None)
