# Na podstawie erlamsa/clients/erlamsa_python_client.py
# Importowanie odpowiednich bibliotek
import httplib
import socket
import sys
import time
from binascii import hexlify as hexa # Zaimportowanie funkcji hexlify z modulu binascii z aliasem hexa()

erlamsa_url = '127.0.0.1:17771' # adres naszego serwera HTTP erlamsy
original_string = "KSTET 1234" # bazowy string do fuzzera
iter = 1
fuzzed_string = '' # zmienna, ktora przechowuje przedostania wylosowana wartosc

while True: # nieskonczona petla iteracyjna
	last = fuzzed_string

	print 'Fuzzing cycle: ' + str(iter)
	iter += 1
	httpconn = httplib.HTTPConnection(erlamsa_url) # ustanowienie polaczenia z serwerem HTTP erlamsy
	headers = {"content-type": "application/octet-stream"} # sprecyzowanie naglowkow
	httpconn.request('POST', '/erlamsa/erlamsa_esi:fuzz', original_string, headers) # wyslanie zapytania do serwera
	response = httpconn.getresponse() # przypisanie odpowiedzi do zmiennej

	fuzzed_string = response.read() # Odczytanie odpowiedzi i skonfigurowanie naglowka

	print '-----------\n'
	print fuzzed_string
	print hexa(fuzzed_string)
	print '-----------\n'

	host = '192.168.56.101' # adres IP ofiary
	port = 9999 # port vulnservera
	
	try: # obsluga wyjatku podczas laczenia sie z serwerem
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Skonfigurowanie socketu do polaczenia
		'''
		Zgodnie z socket.h: http://pubs.opengroup.org/onlinepubs/7908799/xns/syssocket.h.html
		SOCK_STREAM	<- stream (connection) socket
		AF_INET <- Internet IP Protocol
		
		'''
		s.settimeout(1.0) # timeout po ktorym zwrocony bedzie wyjatek

		connect = s.connect((host,port)) # polaczenie z usluga
		data = s.recv(128) # Sprawdzic czy to potrzebne
		s.send(fuzzed_string) # Wyslanie wygenerowanego stringa

	except Exception, e: # obsluga wyjatku
		print("socket() failed -> " + str(e)) # wyswietlenie powodu wyjatku
		print("Last sent fuzzed string: " + last) # wyswietlenie ostatniego, wygenerowanego stringa
		print("Last sent fuzzed string (hex): " + hexa(last)) # jw. tylko z formie hex 
		sys.exit(1) # zamkniecie aplikacji

	time.sleep(0.1) # opoznienie dzialania naszego fuzzera o 0.1 s

'''
socket() failed -> timed out
Last sent fuzzed string: 

Last sent fuzzed string (hex): 4b535445542031323334343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343131363735f3a081ac34343434
~ $:
'''
	
