# cs4404-mission3

Team: Matthew Collins, Philippe Lessard, Jacob Tutlis

For this mission, we designed a command and control system that sent data through covert channels using NTP packets. NTP is the Network Time Protocol that is used to synchronize the clocks between computers. NTP packets have a reference ID field that is used to identify the IP of the source server, however, we used this field to transmit our commands to appear as an IP address in this field. The infected host reads the hidden instructions in the NTP packets and launches an attack on another machine, with the IP address of that machine being sent in the same NTP packets. 

For our defense, we were able to analyze the time between NTP packets and determine if those packets met the distinct pattern in which NTP packets are sent. We were also able to analyze the reference ID field and determine if the IP address was a known valid NTP server.  
