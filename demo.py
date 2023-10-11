#!/usr/bin/python3

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
Demo
"""

import emyzelium as emz

import curses
import random
import sys
import time


# Of course, person_SECRETKEY should be known only to that person
# Here they are "revealed" at once for demo purpose

ALIEN_SECRETKEY = "gr6Y.04i(&Y27ju0g7m0HvhG0:rDmx<Y[FvH@*N("
ALIEN_PUBLICKEY = "iGxlt)JYh!P9xPCY%BlY4Y]c^<=W)k^$T7GirF[R"
ALIEN_ONION = "PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOL" # from service_dir/hostname, without .onion
ALIEN_PORT = 60847

JOHN_SECRETKEY = "gbMF0ZKztI28i6}ax!&Yw/US<CCA9PLs.Osr3APc"
JOHN_PUBLICKEY = "(>?aRHs!hJ2ykb?B}t6iGgo3-5xooFh@9F/4C:DW"
JOHN_ONION = "PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOL" # from service_dir/hostname, without .onion
JOHN_PORT = 60848

MARY_SECRETKEY = "7C*zh5+-8jOI[+^sh[dbVnW{}L!A&7*=j/a*h5!Y"
MARY_PUBLICKEY = "WR)%3-d9dw)%3VQ@O37dVe<09FuNzI{vh}Vfi+]0"
MARY_ONION = "PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOLDER PLACEHOL" # from service_dir/hostname, without .onion
MARY_PORT = 60849


def time_musec(): # microseconds since Unix epoch
	if sys.version_info >= (3, 7):
		return time.time_ns() // 1000
	else:
		return round(time.time() * 1e6)


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


class Other:
	def __init__(self, name, publickey):
		self.name = name
		self.publickey = publickey


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


	def add_other(self, name, publickey, onion, port):
		ehypha, _ = self.efunguz.add_ehypha(publickey, onion, port)
		ehypha.add_etale("")
		ehypha.add_etale("zone")
		self.others.append(Other(name, publickey))


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

		t_start = time_musec()

		t_last_emit = -65536.0
		t_last_render = -65536.0

		while not quit:
			t = 1e-6 * (time_musec() - t_start)

			if t - t_last_render > 1.0 / self.framerate:
				scr.erase()

				if render:
					self.render(scr, paused)
				else:
					scr.addstr(0, 0, "Render OFF")
				scr.addstr((h >> 1) + 2, 0, f"This realm: \"{self.name}'s\" (birth {self.birth}, survival {self.survival}), SLE {t - t_last_emit:.1f}, autoemit ({self.autoemit_interval:.1f}) "+ ("ON" if autoemit else "OFF"))
				scr.addstr((h >> 1) + 3, 0, f"Other realms: ")
				for i_other in range(len(self.others)):
					that = self.others[i_other]
					that_t_in = self.efunguz.get_ehypha(that.publickey)[0].get_etale("zone")[0].t_in
					scr.addstr((", " if (i_other > 0) else "") + f"[{i_other + 1}] \"{that.name}'s\" (SLU {t - 1e-6 * (that_t_in - t_start):.1f})")
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
					that = self.others[i_other]
					that_zone = self.efunguz.get_ehypha(that.publickey)[0].get_etale("zone")[0]
					self.put_etale_to_zone(that_zone.parts)

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


def app_realm(scr, name):
	name = name.capitalize()
	if name == "Alien":
		secretkey = ALIEN_SECRETKEY
		pubport = ALIEN_PORT
		that1_name = "John"
		that1_publickey = JOHN_PUBLICKEY
		that1_onion = JOHN_ONION
		that1_port = JOHN_PORT
		that2_name = "Mary"
		that2_publickey = MARY_PUBLICKEY
		that2_onion = MARY_ONION
		that2_port = MARY_PORT
		birth = {3, 4}
		survival = {3, 4} # 3-4 Life
	elif name == "John":
		secretkey = JOHN_SECRETKEY
		pubport = JOHN_PORT
		that1_name = "Alien"
		that1_publickey = ALIEN_PUBLICKEY
		that1_onion = ALIEN_ONION
		that1_port = ALIEN_PORT
		that2_name = "Mary"
		that2_publickey = MARY_PUBLICKEY
		that2_onion = MARY_ONION
		that2_port = MARY_PORT
		birth = {3}
		survival = {2, 3} # classic Conway's Life
	elif name == "Mary":
		secretkey = MARY_SECRETKEY
		pubport = MARY_PORT
		that1_name = "Alien"
		that1_publickey = ALIEN_PUBLICKEY
		that1_onion = ALIEN_ONION
		that1_port = ALIEN_PORT
		that2_name = "John"
		that2_publickey = JOHN_PUBLICKEY
		that2_onion = JOHN_ONION
		that2_port = JOHN_PORT
		birth = {3}
		survival = {2, 3} # classic Conway's Life		
	else:
		print(f"Unknown realm name: {name}. Must be \"Alien\", \"John\", or \"Mary\".")
		return

	init_term_graphics(scr)

	width = curses.COLS - 2
	height = (curses.LINES - 8) << 1 # even

	realm = Realm_CA(name, secretkey, set(), pubport, width, height, birth, survival)

	# Uncomment to restrict: Alien gets data from John and Mary; John gets data from Alien but not from Mary; Mary gets data from neither Alien, nor John
	# realm.efunguz.add_whitelist_publickeys({that1_publickey})

	realm.add_other(that1_name, that1_publickey, that1_onion, that1_port)
	realm.add_other(that2_name, that2_publickey, that2_onion, that2_port)

	realm.reset()

	realm.run(scr)	


def main():
	if len(sys.argv) < 2:
		print("Syntax:")
		print("demo <Alien|John|Mary>")
	else:
		curses.wrapper(app_realm, sys.argv[1])

main()
