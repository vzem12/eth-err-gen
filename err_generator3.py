#Python 3.9

#ONLY Intel e1000, e1000e Ethernet card


from __future__ import print_function
import os
from time import sleep
from socket import *
from scapy.all import *
from portio import *
import zlib

eth = "enp3s0f1"		#Имя Ethernet интерфейса
wlan = "wlp6s0"		#Имя WiFi интерфейса 
p_count = 150000000000		#Количество отправляемых пакетов
p_inter = 0		#Интервал между отправкой пакетов (в секундах)
src = b'\x18\xc0\x4d\x05\xe2\x9c'	#МАК адрес источника
dst = b'\x10\xa3\xb8\x40\x00\x70'	#МАК адрес получателя
csum = b'\x09\x09\x09\x01'	#Контролльная сумма для подмены
rt_mac = "10:a3:b8:27:8a:e8"
rt_ip = "192.168.0.1"

pci = "03:00.1"	#адрес pci сетевой карты ethtool -i ethX

eth_vendor = "Intel" #Realtek or Intel

preamble = b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'


def CRCEthernetGen():

	os.system('ethtool -K %s tx off' % eth)	#Отключение записи FCS в конец пакета на сетевой карте

	print ('\n\n')
	s = socket.socket(AF_PACKET, SOCK_RAW)

	if eth_vendor == "Intel":
		s.setsockopt(SOL_SOCKET,43,1) #Включить опцию SO_NOFCS /lib/modules/5.10.0-kali4-amd64/source/include/uapi/asm-generic/socket.h
	
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)|0b10000000000000000, ioport + 0x40)
	
	s.bind((eth, 0))
	payload = bytes(("["*30)+"PAYLOAD"+("]"*30), 'utf-8')
	ethertype = b"\x08\x01"
	p_len = b'\x00\x5F'
	packet = dst+src+ethertype+p_len+payload+csum

	print ('Start transmitting...\n\n')

	for i in range(p_count):
		sleep(p_inter)
		s.send(packet)
		print ('.', end = "")
		

	print ('\n\n\n')
	print ("Transmitted %d packets with bad FCS \n\n" % p_count)
	
	if eth_vendor == "Intel":
		os.system('ethtool -K %s tx on' % eth)	#Включение записи FCS в конец пакета на сетевой карте
		
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)^0b10000000000000000, ioport + 0x40)
		
	return None


def CRCWiFiGen():
	
	os.system('ethtool -K %s tx off' % wlan) #Отключение записи FCS в конец пакета на сетевой карте

	print ('\n\n')

	s = socket.socket(AF_PACKET, SOCK_RAW)
	#s.setsockopt(SOL_SOCKET,43,1)
	s.bind((wlan, 0))
	payload = bytes(("["*30)+"PAYLOAD"+("]"*30), 'utf-8')
	ethertype = b"\x08\x01"

	print ('Start transmitting...\n\n')

	for i in range(p_count):
		s.send(dst+src+ethertype+payload+csum)
		print ('.', end = "")
		

	print ('\n\n\n')
	print ("Transmitted %d packets with bad FCS \n\n" % p_count)

	os.system('ethtool -K %s tx on' % wlan)	#Включение записи FCS в конец пакета на сетевой карте
	return None

def UndersizeGen():
	
	if eth_vendor == "Intel":
	
		ioport = int("0x"+subprocess.check_output('setpci -s %s 18.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI 
		
		iopl(3)	#Включаем полный доступ к I/O портам
		
		outl_p(0x400, ioport)	#В I/O порт со смещением 0x00 (IOADDR) записываем смещение регистра TCTL (Transmit Control)
		sleep(1)
		outl_p(0x3103F0F2, ioport+0x04)	#В I/O порт со смещением 0x04 (IODATA) записываем новое значение регистра (изменяем байт 3 с 1 на 0 Pad Short Packet disable для отключения дополнения пакета меньше 60 байт нулями
		sleep(1)
		
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)|0b10000000000000000, ioport + 0x40)
		
	s = socket.socket(AF_PACKET, SOCK_RAW)
	#s.setsockopt(SOL_SOCKET,43,1)
	s.bind((eth, 0))
	
	payload = bytes(("["*17)+"PAYLOAD"+("]"*18), 'utf-8')
	ethertype = b"\x08\x01"
	
	packet = dst+src+ethertype+payload
	
	print ('Start transmitting...\n\n')
	
	if eth_vendor == "Intel":

		for i in range(p_count):
			sleep(p_inter)
			s.send(packet)
			print ('.', end = "")
			
	if eth_vendor == "Realtek":
		
		valid_csum = b''
		crc = zlib.crc32(packet) & 0xFFFFFFFF
		for i in range(4):
			byte=(crc >> (8*i)) & 0xFF
			valid_csum = valid_csum + bytes(bytearray([byte]))
		
		for i in range(p_count):
			sleep(p_inter)
			s.send(packet+valid_csum)
			print ('.', end = "")
		
	print ('\n\n\n')
	print ("Transmitted %d Undersize packets\n\n" % p_count)
	
	if eth_vendor == "Intel":
	
		outl_p(0x400, ioport)	#В I/O порт со смещением 0x00 (IOADDR) записываем смещение регистра TCTL (Transmit Control)
		sleep(1)
		outl_p(0x3103F0FA, ioport+0x04)	#В I/O порт со смещением 0x04 (IODATA) записываем новое значение регистра (изменяем байт 3 с 0 на 1 Pad Short Packet enable для включения дополнения пакета меньше 60 байт нулями
		sleep(1)
		
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)^0b10000000000000000, ioport + 0x40)
	
	return None
	

def FragmentGen():
	
	if eth_vendor == "Intel":
	
		ioport = int("0x"+subprocess.check_output('setpci -s %s 18.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI 
		
		iopl(3)	#Включаем полный доступ к I/O портам
		
		outl_p(0x400, ioport)	#В I/O порт со смещением 0x00 (IOADDR) записываем смещение регистра TCTL (Transmit Control)
		sleep(1)
		outl_p(0x3103F0F2, ioport+0x04)	#В I/O порт со смещением 0x04 (IODATA) записываем новое значение регистра (изменяем байт 3 с 1 на 0 Pad Short Packet disable для отключения дополнения пакета меньше 60 байт нулями)
		sleep(1)
		s.setsockopt(SOL_SOCKET,43,1) #Включить опцию SO_NOFCS /lib/modules/5.10.0-kali4-amd64/source/include/uapi/asm-generic/socket.h
		
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)|0b10000000000000000, ioport + 0x40)
	
	s = socket.socket(AF_PACKET, SOCK_RAW)
	
	s.bind((eth, 0))
	
	payload = bytes(("["*20)+"PAYLOAD"+("]"*17), 'utf-8')
	ethertype = b"\x08\x01"
	
	print ('Start transmitting...\n\n')

	for i in range(p_count):
		sleep(p_inter)
		s.send(dst+src+ethertype+payload+csum)
		print ('.', end = "")
		
	print ('\n\n\n')
	print ("Transmitted %d Fragment packets\n\n" % p_count)
	
	if eth_vendor == "Intel":
		os.system('ethtool -K %s tx on' % eth)	#Включение записи FCS в конец пакета на сетевой карте
		outl_p(0x400, ioport)	#В I/O порт со смещением 0x00 (IOADDR) записываем смещение регистра TCTL (Transmit Control)
		sleep(1)
		outl_p(0x3103F0FA, ioport+0x04)	#В I/O порт со смещением 0x04 (IODATA) записываем новое значение регистра (изменяем байт 3 с 0 на 1 Pad Short Packet enable для включения дополнения пакета меньше 60 байт нулями)
		sleep(1)
		
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)^0b10000000000000000, ioport + 0x40)
		
	return None
	
def OversizeGen():
	
	os.system('ifconfig %s mtu 9000' % eth)
	os.system('ifconfig %s mtu 9000' % eth)
	s = socket.socket(AF_PACKET, SOCK_RAW)
	#s.setsockopt(SOL_SOCKET, SO_PRIORITY, 6)
	s.bind((eth, 0))
	payload = bytes(("["*750)+"PAYLOAD"+("]"*750), 'utf-8')
	ethertype = b"\x08\x01"
	
	print ('Start transmitting...\n\n')

	for i in range(p_count):
		sleep(p_inter)
		s.send(dst+src+ethertype+payload)
		print ('.', end = "")
		
	print ('\n\n\n')
	print ("Transmitted %d Oversize packets\n\n" % p_count)
	s.close()
	#os.system('ifconfig %s mtu 1518' % eth)
	return None
	
def JabberGen():
	
	os.system('ifconfig %s mtu 9000' % eth)
	os.system('ifconfig %s mtu 9000' % eth)
	os.system('ethtool -K %s tx off' % eth)	#Отключение записи FCS в конец пакета на сетевой карте
	
	print ('\n\n')

	s = socket.socket(AF_PACKET, SOCK_RAW)
	
	if eth_vendor == "Intel":
		s.setsockopt(SOL_SOCKET,43,1) #Включить опцию SO_NOFCS /lib/modules/5.10.0-kali4-amd64/source/include/uapi/asm-generic/socket.h
	
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)|0b10000000000000000, ioport + 0x40)
	
	s.bind((eth, 0))
	payload = bytes(("["*750)+"PAYLOAD"+("]"*750), 'utf-8')
	ethertype = b"\x08\x01"

	print ('Start transmitting...\n\n')

	for i in range(p_count):
		sleep(p_inter)
		s.send(dst+src+ethertype+payload+csum)
		print ('.', end = "")
		

	print ('\n\n\n')
	print ("Transmitted %d Jabber packets \n\n" % p_count)

	os.system('ethtool -K %s tx on' % eth)	#Включение записи FCS в конец пакета на сетевой карте
	#os.system('ifconfig %s mtu 1518' % eth)
	
	if eth_vendor == "Intel":
		os.system('ethtool -K %s tx on' % eth)	#Включение записи FCS в конец пакета на сетевой карте
		
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)^0b10000000000000000, ioport + 0x40)
		
	return None
	
	
def CPUUtil():
	ether = Ether(dst=rt_mac)
	ip = IP(dst=rt_ip)
	udp = UDP(sport=80, dport=80)
	payload = Raw(load=bytes(("["*30)+"PAYLOAD"+("]"*30), 'utf-8'))
	packet = ether/ip/udp/payload
	
	sendp(packet, count=p_count, inter=p_inter)
	return None







	
def TEST():
	if eth_vendor == "Intel":
	
		ioport = int("0x"+subprocess.check_output('setpci -s %s 18.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI 
		
		iopl(3)	#Включаем полный доступ к I/O портам
		
		outl_p(0x400, ioport)	#В I/O порт со смещением 0x00 (IOADDR) записываем смещение регистра TCTL (Transmit Control)
		sleep(1)
		outl_p(0x3103F0F2, ioport+0x04)	#В I/O порт со смещением 0x04 (IODATA) записываем новое значение регистра (изменяем байт 3 с 1 на 0 Pad Short Packet disable для отключения дополнения пакета меньше 60 байт нулями
		sleep(1)
		
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)|0b10000000000000000, ioport + 0x40)
		
	s = socket.socket(AF_PACKET, SOCK_RAW)
	#s.setsockopt(SOL_SOCKET,43,1)
	s.bind((eth, 0))
	
	payload = bytes(("["*17)+"PAYLOAD"+("]"*18), 'utf-8')
	ethertype = b"\x08\x01"
	
	packet = dst+src+ethertype+payload
	
	print ('Start transmitting...\n\n')
	
	if eth_vendor == "Intel":

		for i in range(p_count):
			sleep(p_inter)
			s.send(packet)
			print ('.', end = "")
			
	if eth_vendor == "Realtek":
		
		valid_csum = b""
		
		print(packet)
		crc = zlib.crc32(packet) & 0xFFFFFFFF
		for i in range(4):
			byte=(crc >> (8*i)) & 0xFF
			print(byte)
			valid_csum = valid_csum + bytes(bytearray([byte]))
		print(valid_csum)
		
		for i in range(p_count):
			sleep(p_inter)
			s.send(packet+valid_csum)
			print ('.', end = "")
		
	print(valid_csum)
	print ('\n\n\n')
	print ("Transmitted %d Undersize packets\n\n" % p_count)
	
	if eth_vendor == "Intel":
	
		outl_p(0x400, ioport)	#В I/O порт со смещением 0x00 (IOADDR) записываем смещение регистра TCTL (Transmit Control)
		sleep(1)
		outl_p(0x3103F0FA, ioport+0x04)	#В I/O порт со смещением 0x04 (IODATA) записываем новое значение регистра (изменяем байт 3 с 0 на 1 Pad Short Packet enable для включения дополнения пакета меньше 60 байт нулями
		sleep(1)
		
	if eth_vendor == "Realtek":
		ioport = int("0x"+subprocess.check_output('setpci -s %s 10.l' % pci, shell=True).decode("utf-8"),16)-1 	#Получаем номер I/O порта из BAR3 PCI
		iopl(3)
		outl(inl_p(ioport + 0x40)^0b10000000000000000, ioport + 0x40)
	
	return None
	
print ("1. CRC errors on Ethernet")
print ("2. CRC errors on WiFi")
print ("3. Undersize on Ethernet")
print ("4. Fragment on Ethernet")
print ("5. Oversize on Ethernet")
print ("6. Jabber on Ethernet")
print ("7. CPU utilization")
print()

err_type = int(input("Choise type of errors: "))

if err_type == 1: CRCEthernetGen()
if err_type == 2: CRCWiFiGen()
if err_type == 3: UndersizeGen()
if err_type == 4: FragmentGen()
if err_type == 5: OversizeGen()
if err_type == 6: JabberGen()
if err_type == 7: CPUUtil()
if err_type == 0: TEST()

