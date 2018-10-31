# Na podstawie erlamsa/clients/erlamsa_python_client.py
# Importowanie odpowiednich bibliotek
# coding: utf-8
import httplib
import socket
import sys
import time
from binascii import hexlify as hexa # Zaimportowanie funkcji hexlify z modułu binascii z aliasem hexa()

erlamsa_url = '127.0.0.1:17771' # Adres naszego serwera HTTP erlamsy
original_string = "KSTET 1234" # Bazowy string do fuzzera
iteration = 1
fuzzed_string = '' # Zmienna, która przechowuje przedostatnią wylosowaną wartość

while True: # Nieskończona pętla iteracyjna
	last = fuzzed_string

	print 'Fuzzing cycle: ' + str(iteration)
	iteration += 1
	httpconn = httplib.HTTPConnection(erlamsa_url) # Ustanowienie połączenia z serwerem HTTP erlamsy
	headers = {"content-type": "application/octet-stream"} # Sprecyzowanie nagłówków
	httpconn.request('POST', '/erlamsa/erlamsa_esi:fuzz', original_string, headers) # Wysłanie zapytania do serwera
	response = httpconn.getresponse() # Przypisanie odpowiedzi do zmiennej

	fuzzed_string = response.read() # Odczytanie odpowiedzi i skonfigurowanie nagłówka

	print '-----------\n'
	print fuzzed_string
	print hexa(fuzzed_string)
	print '-----------\n'

	host = '192.168.56.101' # Adres IP ofiary
	port = 9999 # Port vulnservera
	
	try: # Obsługa wyjątku podczas łączenia sie z serwerem
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Skonfigurowanie socketu do polaczenia
		'''
		Zgodnie z socket.h: http://pubs.opengroup.org/onlinepubs/7908799/xns/syssocket.h.html
		SOCK_STREAM	<- stream (connection) socket
		AF_INET <- Internet IP Protocol
		
		'''
		s.settimeout(1.0) # Timeout po którym zwrócony będzie wyjątek

		connect = s.connect((host,port)) # Połączenie z usługą
		data = s.recv(128) # Przypisanie odpowiedzi serwera do zmiennej
		s.send(fuzzed_string) # Wysłanie wygenerowanego stringa

	except Exception, e: # Obsługa wyjątku
		print("socket() failed -> " + str(e)) # Wyświetlenie powodu wyjątku
		print("Last sent fuzzed string: " + last) # Wyświetlenie ostatniego, wygenerowanego stringa
		print("Last sent fuzzed string (hex): " + hexa(last)) # Jw. tylko z formie hex 
		sys.exit(1) # Zamknięcie aplikacji

	time.sleep(0.1) # Opóznienie działania naszego fuzzera o 0.1 s

	
