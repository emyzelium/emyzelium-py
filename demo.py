#!/usr/bin/python3

"""
Emyzelium (Python)

Emyzelium is another gigathin wrapper around ZeroMQ's Publish-Subscribe and
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
Demo
"""

import emyzelium as emz

import curses
import random
import sys
import time


def init_term_graphics(scr):
	scr.nodelay(True)
	curses.curs_set(0)

	if curses.can_change_color():
		curses.init_color(0, 0, 0, 0)

	if curses.has_colors():
		for bc in range(8): # is it minimum of curses.COLORS?
			for fc in range(8):
				if (bc > 0) or (fc > 0):
					curses.init_pair((bc << 3) + fc, fc, bc)
		


def print_rect(scr, x, y, w, h):
	scr.addstr(y, x, "┌")
	scr.addstr(y, x + w - 1, "┐")
	scr.addstr(y + h - 1, x + w - 1, "┘")
	scr.addstr(y + h - 1, x, "└")
	for i in range(1, h - 1):
		scr.addstr(y + i, x, "│")
		scr.addstr(y + i, x + w - 1, "│")
	for j in range(1, w - 1):
		scr.addstr(y, x + j, "─")
		scr.addstr(y + h - 1, x + j, "─")


class Realm_CA:
	def __init__(self, name, secretkey, whitelist_publickeys, pubport, width, height, birth, survival, autoemit_interval=4.0, framerate=30):
		if (height & 1) != 0:
			raise SystemError("field height must be even")

		self.name = name
		self.efunguz = emz.Efunguz(secretkey, whitelist_publickeys, pubport)
		self.width = width
		self.height = height
		self.cells = [[0 for x in range(self.width)] for y in range(self.height)] # bits: 0 - current state, 1-4 - number of alive neighbours
		self.birth = birth
		self.survival = survival

		self.autoemit_interval = autoemit_interval
		self.framerate = framerate;

		self.others = []

		self.i_turn = 0

		self.cursor_x = self.width >> 1
		self.cursor_y = self.height >> 1


	def add_other(self, name, publickey, connpoint=None):
		ehypha, ew = self.efunguz.add_ehypha(publickey, connpoint)
		selfdesc, ew = ehypha.add_etale("")
		zone, ew = ehypha.add_etale("zone")
		self.others.append([name + "'s", selfdesc, zone])


	def add_ecatal(self, publickey, is_to, beacon_connpoint, is_from, pubsub_connpoint):
		if is_to:
			self.efunguz.add_ecatal_to(publickey, beacon_connpoint)
		if is_from:
			self.efunguz.add_ecatal_from(publickey, pubsub_connpoint)


	def flip(self, y=None, x=None):
		y = self.cursor_y if y == None else y
		x = self.cursor_x if x == None else x
		self.cells[y][x] ^= 1


	def clear(self):
		for y in range(self.height):
			for x in range(self.width):
				self.cells[y][x] = 0
		self.i_turn = 0


	def reset(self):
		for y in range(self.height):
			for x in range(self.width):
				self.cells[y][x] = random.randrange(2)
		self.i_turn = 0


	def render(self, scr, show_cursor=False):
		h, w = self.height, self.width
		w_tert = w // 3
		print_rect(scr, 0, 0, w + 2, (h >> 1) + 2) # grey on black
		scr.addstr(0, w_tert, "┬┬")
		scr.addstr(0, w - w_tert, "┬┬")
		scr.addstr(1 + (h >> 1), w_tert, "┴┴")
		scr.addstr(1 + (h >> 1), w - w_tert, "┴┴")
		scr.addstr(0, 2, "[ From others ]")
		scr.addstr(0, 3 + w - w_tert, "[ To others ]")
		for i in range(h >> 1):
			y = i << 1
			row_str = ""
			for x in range(w):
				row_str += [[" ", "▀"], ["▄", "█"]][self.cells[y + 1][x] & 1][self.cells[y][x] & 1]
			scr.addstr(1 + i, 1, row_str, curses.color_pair(0x7) | curses.A_BOLD) # white on black

		status_str = f"[ T = {self.i_turn}"

		if show_cursor:
			i = self.cursor_y >> 1
			m = self.cursor_y & 1
			cell_high, cell_low = self.cells[i << 1][self.cursor_x] & 1, self.cells[(i << 1) + 1][self.cursor_x] & 1

			char = [[["▀",   "▄"],   ["▀",   "▀"]],   [["▄",   "▄"],   ["▄",   "▀"]]][cell_low][cell_high][m]
			clrp = [[[(1,0), (1,0)], [(3,0), (7,1)]], [[(7,1), (3,0)], [(7,3), (7,3)]]][cell_low][cell_high][m]
			bold = [[[0,      0],     [0,    1]],     [[1,     0],     [1,     1]]][cell_low][cell_high][m]
			# Exercise: compactify

			scr.addstr(1 + i, 1 + self.cursor_x, char, curses.color_pair(clrp[0] | (clrp[1] << 3)) | (curses.A_BOLD * bold))

			status_str += f", X = {self.cursor_x}, Y = {self.cursor_y}, C = {self.cells[self.cursor_y][self.cursor_x] & 1}"

		status_str += " ]"
		scr.addstr(1 + (h >> 1), 1 + (w >> 1) - (len(status_str) >> 1), status_str)


	def move_cursor(self, dy, dx):
		self.cursor_x = max(0, min(self.width - 1, self.cursor_x + dx))
		self.cursor_y = max(0, min(self.height - 1, self.cursor_y + dy))


	def turn(self):
		h, w = self.height, self.width
		# Count alive neighbours
		for y in range(h):
			for x in range(w):
				if self.cells[y][x] & 1 != 0:
					for ny in range(y-1, y+2):
						if (ny >= 0) and (ny < h):
							for nx in range(x-1, x+2):
								if ((ny != y) or (nx != x)) and (nx >=0) and (nx < w):
									self.cells[ny][nx] += 2
		# Update
		for y in range(h):
			for x in range(w):
				c = self.cells[y][x]
				if c & 1 != 0:
					c = 1 if ((c >> 1) in self.survival) else 0
				else:
					c = 1 if ((c >> 1) in self.birth) else 0
				self.cells[y][x] = c
		self.i_turn += 1


	def get_etale_from_zone(self):
		h, w = self.height, self.width
		zh = h
		zw = w // 3
		zone = bytearray(zh * zw) # could compress to bits...
		for y in range(h):
			for x in range(zw):
				zone[y * zw + x] = self.cells[y][w - zw + x] & 1
		return [zh.to_bytes(2, byteorder="little"), zw.to_bytes(2, byteorder="little"), zone] # parts


	def put_etale_to_zone(self, parts):
		if len(parts) == 3:
			if (len(parts[0]) == 2) and (len(parts[1]) == 2):
				szh, szw = int.from_bytes(parts[0], byteorder="little"), int.from_bytes(parts[1], byteorder="little")
				if len(parts[2]) == szh * szw:
					dzh = min(szh, self.height)
					dzw = min(szw, self.width // 3)
					for y in range(dzh):
						for x in range(dzw):
							self.cells[y][x] = parts[2][y * szw + x] & 1


	def emit_etales(self):
		self.efunguz.emit_etale("", ["zone".encode("utf8"), "2B height (h), 2B width (w), h×wB zone by rows".encode("utf8")])
		self.efunguz.emit_etale("zone", self.get_etale_from_zone())


	def update_efunguz(self):
		self.efunguz.update()


	def run(self, scr):
		h, w = self.height, self.width

		quit = False
		paused = False
		render = True
		autoemit = True

		t_last_emit = 0
		t_last_render = 0

		while not quit:
			t = time.time()

			if t - t_last_render > 1.0 / self.framerate:
				scr.erase()

				if render:
					self.render(scr, paused)
				else:
					scr.addstr(0, 0, "Render OFF")
				scr.addstr((h >> 1) + 2, 0, f"This realm: \"{self.name}\" (birth {self.birth}, survival {self.survival}), SLE {t - t_last_emit:.1f}, autoemit ({self.autoemit_interval:.1f}) "+ ("ON" if autoemit else "OFF"))
				scr.addstr((h >> 1) + 3, 0, f"Other realms: ")
				for i_other in range(len(self.others)):
					that_name, _, that_etale_zone = self.others[i_other]
					scr.addstr((", " if (i_other > 0) else "") + f"[{i_other + 1}] \"{that_name}\" (SLU {t - that_etale_zone.t_in * 1e-6:.1f})")
				scr.addstr(curses.LINES - 3, 0, "[Q] quit, [C] clear, [R] reset, [V] render on/off, [P] pause/resume")
				scr.addstr(curses.LINES - 2, 0, "[A] autoemit on/off, [E] emit, [1-9] import")
				scr.addstr(curses.LINES - 1, 0, "If paused: [T] turn, [→ ↑ ← ↓] move cursor, [ ] flip cell")

				scr.refresh()

				t_last_render = t

			if autoemit and (t - t_last_emit > self.autoemit_interval):
				self.emit_etales()
				t_last_emit = t

			self.update_efunguz()

			if not paused:
				self.turn()

			ch = scr.getch()
			
			if ch in [ord('q'), ord('Q')]:
				quit = True
			elif ch in [ord('c'), ord('C')]:
				self.clear()
			elif ch in [ord('r'), ord('R')]:
				self.reset()
			elif ch in [ord('v'), ord('V')]:
				render = not render
			elif ch in [ord('p'), ord('P')]:
				paused = not paused
			elif ch in [ord('a'), ord('A')]:
				autoemit = not autoemit
			elif ch in [ord('e'), ord('E')]:
				self.emit_etales()
				t_last_emit = t
			elif (ch >= ord('1')) and (ch <= ord('9')):
				i_other = ch - ord('1')
				if i_other < len(self.others):
					that_etale_zone = self.others[i_other][2]
					self.put_etale_to_zone(that_etale_zone.parts)

			if paused:
				if ch in [ord('t'), ord('T')]:
					self.turn()
				elif ch == ord(' '):
					self.flip()
				elif ch == curses.KEY_RIGHT:
					self.move_cursor(0, 1)
				elif ch == curses.KEY_UP:
					self.move_cursor(-1, 0)
				elif ch == curses.KEY_LEFT:
					self.move_cursor(0, -1)
				elif ch == curses.KEY_DOWN:
					self.move_cursor(1, 0)


def app_realm(scr, name, ecatal_ip):
	thisname = name	+ "'s"
	if name == "Alien":
		secretkey = "gr6Y.04i(&Y27ju0g7m0HvhG0:rDmx<Y[FvH@*N("
		pubport = emz.DEF_EFUNGI_PUBSUB_PORT + 1
		that1_name = "John"
		that1_publickey = "(>?aRHs!hJ2ykb?B}t6iGgo3-5xooFh@9F/4C:DW"
		that2_name = "Mary"
		that2_publickey = "WR)%3-d9dw)%3VQ@O37dVe<09FuNzI{vh}Vfi+]0"
		birth = {3, 4}
		survival = {3, 4} # 3-4 Life
	elif name == "John":
		secretkey = "gbMF0ZKztI28i6}ax!&Yw/US<CCA9PLs.Osr3APc"
		pubport = emz.DEF_EFUNGI_PUBSUB_PORT + 2
		that1_name = "Alien"
		that1_publickey = "iGxlt)JYh!P9xPCY%BlY4Y]c^<=W)k^$T7GirF[R"
		that2_name = "Mary"
		that2_publickey = "WR)%3-d9dw)%3VQ@O37dVe<09FuNzI{vh}Vfi+]0"
		birth = {3}
		survival = {2, 3} # classic Conway's Life
	elif name == "Mary":
		secretkey = "7C*zh5+-8jOI[+^sh[dbVnW{}L!A&7*=j/a*h5!Y"
		pubport = emz.DEF_EFUNGI_PUBSUB_PORT + 3
		that1_name = "Alien"
		that1_publickey = "iGxlt)JYh!P9xPCY%BlY4Y]c^<=W)k^$T7GirF[R"
		that2_name = "John"
		that2_publickey = "(>?aRHs!hJ2ykb?B}t6iGgo3-5xooFh@9F/4C:DW"
		birth = {3}
		survival = {2, 3} # classic Conway's Life		
	else:
		print(f"Unknown realm name: {name}. Must be \"Alien\", \"John\", or \"Mary\".")
		return

	init_term_graphics(scr)

	width = curses.COLS - 2
	height = (curses.LINES - 8) << 1 # even

	realm = Realm_CA(thisname, secretkey, set(), pubport, width, height, birth, survival)

	realm.add_other(that1_name, that1_publickey)
	realm.add_other(that2_name, that2_publickey)

	if ecatal_ip == "":
		ecatal_ip = emz.DEF_IP

	realm.add_ecatal("d.OT&vpji%VDDI[8QI2L8K]ZiqpwFjxhR{5ftXRp", True, f"tcp://{ecatal_ip}:{emz.DEF_ECATAL_BEACON_PORT + 1}", True, f"tcp://{ecatal_ip}:{emz.DEF_ECATAL_PUBSUB_PORT + 1}")
	realm.add_ecatal("k>Kk(x/V]=y1=1R%0P2+rF@%<=##eJa&BK<PX>50", True, f"tcp://{ecatal_ip}:{emz.DEF_ECATAL_BEACON_PORT + 2}", True, f"tcp://{ecatal_ip}:{emz.DEF_ECATAL_PUBSUB_PORT + 2}")
	realm.add_ecatal("O%[dWs({TBGSfUKlkpcoYHGhCeZLD?[zzjZ7TB9C", True, f"tcp://{ecatal_ip}:{emz.DEF_ECATAL_BEACON_PORT + 3}", True, f"tcp://{ecatal_ip}:{emz.DEF_ECATAL_PUBSUB_PORT + 3}")

	realm.reset()

	realm.run(scr)	


def run_ecatal(name):
	if name == "A":
		ecatal = emz.Ecataloguz("T*t*)FNSa1RSOG9Dbxuvq1M{hE-luf{YjW+8j^@1", dict(), set(), emz.DEF_ECATAL_BEACON_PORT + 1, emz.DEF_ECATAL_PUBSUB_PORT + 1, round(60 * 1e6), round(1 * 1e6), round(0.1 * 1e6))
		ecatal.run(True)
	elif name == "B":
		ecatal = emz.Ecataloguz("+f(o9nJE%H4[f?Z7eZ!>j[+>WVx0EkDVUYbw[B^8", {"iGxlt)JYh!P9xPCY%BlY4Y]c^<=W)k^$T7GirF[R" : "Alien", "(>?aRHs!hJ2ykb?B}t6iGgo3-5xooFh@9F/4C:DW" : "John", "WR)%3-d9dw)%3VQ@O37dVe<09FuNzI{vh}Vfi+]0" : "Mary"}, set(), emz.DEF_ECATAL_BEACON_PORT + 2, emz.DEF_ECATAL_PUBSUB_PORT + 2, round(60 * 1e6), round(1 * 1e6), round(0.1 * 1e6))
		ecatal.run(True)
	elif name == "C":
		ecatal = emz.Ecataloguz("ap:W}bEN0@@>9^>ZcYNDP?Xc6JC8mIIbMw@-zV@c", dict(), set(), emz.DEF_ECATAL_BEACON_PORT + 3, emz.DEF_ECATAL_PUBSUB_PORT + 3, round(60 * 1e6), round(1 * 1e6), round(0.1 * 1e6))
		ecatal.read_beacon_whitelist_publickeys_with_comments("demo_publickeys_with_comments.txt")
		ecatal.read_pubsub_whitelist_publickeys("demo_publickeys_with_comments.txt")
		ecatal.run(True)		
	else:
		print(f"Unknown ecatal name: {name}. Must be \"A\", \"B\", or \"C\".")
		return


def main():
	if len(sys.argv) < 3:
		print("Syntax:")
		print("demo realm <Alien|John|Mary>")
		print("or")
		print("demo ecatal <A|B|C>")
	else:
		if sys.argv[1] == "realm":
			curses.wrapper(app_realm, sys.argv[2], sys.argv[3] if (len(sys.argv) >= 4) else "")
		elif sys.argv[1] == "ecatal":
			run_ecatal(sys.argv[2])
		else:
			print("Unknown 1st arg.")


main()
