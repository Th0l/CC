#cliente
#python3
import random
import hashlib
import time
import others
import sys
from socket import *
from others import Estado
from others import Header
from Crypto.Hash import SHA256


checkNumber = random.randint(0, (2**12)-2) #inicialização do nº sequência, com um valor random, máx 32 bits
seqNumber = 0
#Inicialização socket
socket = socket(AF_INET,SOCK_DGRAM)
host =sys.argv[1] #IP do servidor
nomeFicheiro = sys.argv[2] #Nome do ficheiro a enviar
port = 9999 #porta do cliente
portS = 9000 #porta do servidor
buf = 1024
addr = (host,port)
socket.bind(("0.0.0.0",port))



class Cliente:
	def __init__(self):
		self.estado=Estado.FECHADO #Quando um cliente é criado, este encontra-se "Fechado"
		self.handshake() #Método que liga o cliente ao servidor

	def handshake(self):
		global checkNumber
		while True: #Ciclo até uma ligação com o servidor for estabelecida
			if self.estado == Estado.FECHADO:
				num_seq = checkNumber
				num_ack = 0
				checksum = 0
				syn = 1
				psh = 0
				rst = 0
				ack = 0
				fin = 0
				pdu1 = others.Header(num_seq,num_ack,checksum,syn,psh,rst,ack,fin)
				print("PDU inicial")
				print(pdu1)
				x=pdu1.converte()
				socket.sendto(x,(host,portS)) #Envia PDU inicial
				print("PDU inicial enviado")
				time.sleep(.001) #Sleep para sincronizar cliente e servidor
				print("\n")
				self.estado = Estado.SYN_E

			elif self.estado == Estado.SYN_E:
				try:
					socket.settimeout(10)
					dados, ipS = socket.recvfrom(512)
					z = others.desconverte(dados) #Descomprime o pdu recebido
					print("PDU inicial resposta do servidor recebido")
					print(z)
					if z.num_ack == checkNumber+1 and z.syn == 1 and z.ack ==1:
						print("PDU recebido é válido")
						print("\n")
						checkNumber = random.randint(0, (2**12)-2) #criamos um novo número de sequência
						num_ack = z.num_seq + 1
						num_seq = checkNumber
						checksum = 0
						syn = 0
						psh = 0
						rst = 0
						ack = 1
						fin = 0
						pdu3 = others.Header(num_seq,num_ack,checksum,syn,psh,rst,ack,fin)
						print("PDU ack cliente ao servidor - PDU3")
						print(pdu3)
						x=pdu3.converte()
						socket.sendto(x,(host,portS)) #Envia PDU3
						print("PDU3 enviado")
						time.sleep(.001) #para "sincronizar" cliente e servidor
						self.estado = Estado.ACK_E
					else:
						print("PDU INVÁLIDO")
						print("A reiniciar handshake protocol")
						self.estado = Estado.FECHADO #algo correu mal, volta ao início do handshake
						
				except timeout:
					socket.close()
					estado = Estado.SYN_E
					print("Não foi recebido um syn-ack do servidor, a encerrar sockets, bye-bye")
					break

			elif self.estado == Estado.ACK_E:
				print("--Handshake completed from client's side--\n")
				break

	def termino(self): #Envia um fin para o servidor de modo a terminar a conexão entre ambos
		global checkNumber
		num_ack = checkNumber
		checkNumber = random.randint(0, (2**12)-2)
		num_seq  = num_ack + 1
		checksum = 0
		syn = 0
		psh = 0
		rst = 0
		ack = 0
		fin = 1
		pf1 = others.Header(num_seq,num_ack,checksum,syn,psh,rst,ack,fin)
		print("Pedido de FIN do cliente para o servidor - PF1")
		print(pf1)
		x = pf1.converte()
		socket.sendto(x,(host,portS)) #Envia pf1
		time.sleep(.001)
		print("\n")
		try:
			#Agora ficamos à espera da confirmação pelo servidor
			socket.settimeout(10)
			dados, ipS = socket.recvfrom(512)
			z = others.desconverte(dados) #Descomprime o pdu recebido
			print("FIN do servidor recebido")
			print(z)
			print("\n")
			if z.fin == 1 and z.ack == 1:
				checkNumber = random.randint(0, (2**12)-2)
				num_seq = checkNumber
				num_ack = z.num_ack + 1
				checksum = 0
				syn = 0
				psh = 0
				rst = 0
				ack = 1
				fin = 0
				pf3 = others.Header(num_seq,num_ack,checksum,syn,psh,rst,ack,fin)
				print("Confirmação do FIN do cliente para o servidor - PF3")
				print(pf3)
				x = pf3.converte()
				socket.sendto(x,(host,portS)) #Envia pf3
				print("PF3 enviado")
				time.sleep(.001)
				print("\n")
				socket.close()
				print("Cliente offline")
		except timeout:
			socket.close()
			estado = Estado.FECHADO
			print("Não foi recebido um fin-ack do servidor, a encerrar sockets, bye-bye")

	def enviaDados(self):
		global checkNumber
		socket.sendto(nomeFicheiro.encode(),(host,portS)) #É enviado o nome do ficheiro
		f=open(nomeFicheiro,"rb")
		data = f.read(1024) #São lidos 1024 bytes do ficheiro aberto em modo binário
		tamanho = len(data)
		janela = 0
		checkNumber = -tamanho
		num_seq = checkNumber + tamanho
		while (data): #Enquanto existirem dados para enviar
			while(janela < 50 and data):
				num_ack = num_seq + 1
				checkNumber = num_seq
				syn = 0
				psh = 1
				rst = 0
				ack = 0
				fin = 0
				y= SHA256.new(data) #É criado um checksum
				t = y.hexdigest()[:4]
				q = t.encode()
				checksum = int(q,16) #converte para base 10
				pdu = others.Header(num_seq,num_ack,checksum,syn,psh,rst,ack,fin)
				x = pdu.converte()
				print(pdu)
				print("Tamanho dados enviados: " + str(tamanho) + " bytes\n")
				num_seq = checkNumber + tamanho
				socket.sendto(x+data,(host,portS))
				data = f.read(1024) #São lidos 1024 bytes em binário do ficheiro em questão
				tamanho = len(data)
				janela = janela + 1
			if (data):
				print("A verificar a partir de onde se vai enviar dados")
				data,ipS =socket.recvfrom(1500)
				header = others.desconverte(data)
				num_seq = header.num_seq
				f.seek(header.num_seq,0)
				data = f.read(1024)
				janela = 0
		f.close()
		time.sleep(0.3) #Sleep para dar tempo ao servidor para inicializar o seu processo de finalização

cliente = Cliente() #Cria um cliente e executa o protocolo de handshake
print("A Iniciar envio do ficheiro '" + nomeFicheiro + "'")
cliente.enviaDados() #Envia o ficheiro
print("\n--Iniciar Término de Ligação--")
cliente.termino() #Termina ligação com o cliente
print("Bye-Bye")
