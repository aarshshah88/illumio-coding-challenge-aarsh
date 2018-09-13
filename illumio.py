import time

class Firewall:
	def __init__(self, csv_file_path):
		self.rules_dict = {"outbound": {"udp": {"range": set(),"norange": set()	},
										"tcp": {"range": set(),"norange": set()	}},
					  		"inbound": {"udp": {"range": set(),"norange": set() },
					  					"tcp": {"range": set(),"norange": set() }}}

		with open(csv_file_path, "r") as file:
			#open line by line, seperate by each of the inputs and then construct a rule
			for line in file:
				#represents whether or not the port and the IPaddress are ranges or not
				port_bool = False
				address_range_bool = False
				#splits up the line into different arguements
				list_from_line = [x.strip() for x in line.split(',')]
				#checks if there is a dash in the arguements for port and IP address, if there is update the variables
				if '-' in list_from_line[2]:
					port_bool = True
				if '-' in list_from_line[3]:
					address_range_bool = True

				#create a rule object based on the arguements we extracted and whether or not there were ranges
				rule = Rule(list_from_line[0], list_from_line[1], list_from_line[2], list_from_line[3], port_bool, address_range_bool)

				# if either of them were a range add to a range node in dictionary otherwise to a norange node
				if rule.port_range_bool == True or rule.IP_address_range_bool == True:
					self.rules_dict[rule.direction][rule.protocol]["range"].add(rule)
				else:
					self.rules_dict[rule.direction][rule.protocol]["norange"].add(rule)

	#function to see if a packet gets accepted
	def accept_packet(self, direction, protocol, port, ip_address):
		# get two lists for the specified direction and protocol
		# we have to go through both to check
		list_of_range_rules = self.rules_dict[direction][protocol]["range"]
		list_of_nonrange_rules = self.rules_dict[direction][protocol]["norange"]

		ip_address_converted = convertToNum(ip_address.split('.'))

		ans = False

		# if the rule is in the dictionary as is then we return True

		for rule in list_of_nonrange_rules:

			ans = rule.compare_all_vals(direction, protocol, port, ip_address)
			if ans == True:
				return True

		# if not then we have to check if it would exist within a range of numbers

		for rule in list_of_range_rules:
			# if both port and IP are a range then we have to check if the given rule fits within both of those ranges
			if rule.port_range_bool == True and rule.IP_address_range_bool == True:
				# this code basically splits up the port values into a range based on the hyphen and also converts the IP_addresses
				# into range numbers so we can check if the given IP_address lies within the rule
				range_numbers_port = rule.port.split('-')
				range_numbers_IP = rule.IP_address.split('-')
				range_numbers_IP[0] = convertToNum(range_numbers_IP[0].split('.'))
				range_numbers_IP[1] = convertToNum(range_numbers_IP[1].split('.'))
				if port <= int(range_numbers_port[1]) and int(port >= range_numbers_port[0]) and ip_address_converted <= range_numbers_IP[1] and ip_address_converted >= range_numbers_IP[0]:

					# if they fit within the range of both port and IP we can compare to make sure the direction and protocal match as well
					ans = rule.compare(direction, protocol)


					if ans == True:
						return True

			elif rule.port_range_bool == True:
				# splitting port into its range
				range_numbers_port = rule.port.split('-')
				if port <= int(range_numbers_port[1]) and port >= int(range_numbers_port[0]):
					# same idea as first loop but checking port only
					ans = rule.compare_all_vals_but_port(direction, protocol, ip_address)

					if ans == True:
						return True

			elif rule.IP_address_range_bool == True:
				range_numbers_IP = rule.IP_address.split('-')
				range_numbers_IP[0] = convertToNum(range_numbers_IP[0].split('.'))
				range_numbers_IP[1] = convertToNum(range_numbers_IP[1].split('.'))
				if int(ip_address_converted) <= range_numbers_IP[1] and int(ip_address_converted) >= range_numbers_IP[0]:

					ans = rule.compare_all_vals_but_IP(direction, protocol, port)

					if ans == True:
						return True

		return False



#this creates a rule with each of the inputs as well as a boolean to determine whether or 
class Rule:

	#initializing a rule
	def __init__(self, direction, protocol, port, IP_address, port_range_bool, IP_address_range_bool):
		self.direction = direction
		self.protocol = protocol
		self.port = port
		self.IP_address = IP_address
		self.port_range_bool = port_range_bool
		self.IP_address_range_bool = IP_address_range_bool


	#function for carrying out different types of comparisions

	def compare_vals(self, direction, protocol):
		if direction == self.direction and protocol == self.protocol:
			return True
		return False

	def compare_all_vals(self, direction, protocol, port, IP_address):
		if self.IP_address == IP_address and self.direction == direction and self.protocol == protocol and int(self.port) == port:
			return True
		return False
		
	def compare_all_vals_but_port(self, direction, protocol, IP_address):
		if self.IP_address == IP_address and self.direction == direction and self.protocol == protocol:
			return True
		return False

	def compare_all_vals_but_IP(self, direction, protocol, port):
		if self.direction == direction and self.protocol == protocol and int(self.port) == port:
			return True
		return False

# converts a list of ints into one int
def convertToNum(s):         
	s = ''.join(s)         
	s = int(s)            
	return s


firewall = Firewall("/home/aarsh/Documents/illumio.csv")

a = time.time()

#True
print(firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
#True
print(firewall.accept_packet("inbound", "udp", 53, "192.168.2.1"))
#False
print(firewall.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
#False
print(firewall.accept_packet("inbound", "udp", 24, "52.12.48.92"))
#True
print(firewall.accept_packet("outbound", "tcp", 10500, "192.168.10.11"))

b = time.time()
print(b-a)