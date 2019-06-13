#servidor
#python3
import random
import others
import sys
import select
import hashlib
import os
import time
from socket import *
from others import Estado
from others import Header
from Crypto.Hash import SHA256

checkNumber = -1
estado = Estado.FECHADO #Quando um servidor é criado, este encontra-se "Fechado"
host="0.0.0.0"
port = 9000 #Porta do servidor
portC = 9999 #Porta do cliente
#Inicialização socket
socket = socket(AF_INET,SOCK_DGRAM)
socket.bind(("",port)) #Servidor começa a aceitar conexões
ultimo = 0 #Contador que guarda a posição para a qual é esperada receber dados
contador = 0 #Contador para contar número de Syn enviados
contador2 = 0 #COntador para contar número de Fin enviados

while True:
	if estado == Estado.FECHADO:
		try:
			socket.settimeout(5) #Se o servidor não receber dados durante os primeiros 5 segundos
			dados, ipC = socket.recvfrom(512) #Espera pelo syn do cliente #MAX= 65536 bytes
			z = others.desconverte(dados) #Descomprime o pdu recebido
			print("PDU inicial pedido do cliente recebido")
			print(z)
			print("\n")
			checkNumber = random.randint(0, (2**12)-2) #É criado um novo número de sequência
			num_seq = checkNumber
			num_ack = z.num_seq + 1
			checksum = 0
			syn = 1
			psh = 0
			rst = 0
			ack = 1
			fin = 0
			pdu2 = others.Header(num_seq,num_ack,checksum,syn,psh,rst,ack,fin)
			print("PDU syn+ack servidor para o cliente - PDU2")
			print(pdu2)
			print("\n")
			x=pdu2.converte()
			socket.sendto(x,(ipC[0],portC)) #Envia PDU2
			estado = Estado.SYN_ACK_E
		except timeout:
			socket.close()
			estado = Estado.FECHADO
			print("Nenhum cliente efetuou conexão, a encerrar sockets, bye-bye")
			break

	elif estado == Estado.SYN_ACK_E:
		try:
			socket.settimeout(1) #Se não receber o ack do cliente reenvia pacote
			dados, ipC = socket.recvfrom(512) #Espera pelo ack do cliente #MAX= 65536 bytes
			z = others.desconverte(dados) #Descomprime o pdu recebido
			print("PDU ack do cliente recebido")
			print(z)
			if z.num_ack == checkNumber+1 and z.ack == 1:
				print("PDU VALIDADO")
				checkNumber = z.num_seq
				estado = Estado.ACK_R
				print("--Handshake completed from server's perspective--") #O servidor está pronto a receber dados
				print("\n")
			else:
				print("PDU INVÁLIDO")
				print("A reiniciar servidor")
				estado = Estado.FECHADO
		except timeout:
			estado = Estado.SYN_ACK_E
			print("Não foi recebido um ack do cliente, a reenviar pacote")
			socket.sendto(x,(ipC[0],portC)) #Reenvia PDU2
			contador = contador + 1
			if contador == 10:
				socket.close()
				print("Não foi recebido um ack do cliente, a encerrar socket, bye-bye")
				break

	elif estado == Estado.ACK_R: #Servidor está pronto a receber dados
		data,addr = socket.recvfrom(1500) #Recebe o nome do ficheiro a receber
		nome = data.decode().strip()
		print ("Nome do ficheiro: ",nome) #Imprime o nome do ficheiro
		f = open(nome,'wb') #É criado um ficheiro com o nome recebido

		data,ipC = socket.recvfrom(1500) #Primeiro PDU com dados
		header = others.desconverte(data)
		dados = others.getData(data)
		seek = header.num_seq #Define o byte onde se deve começar a escrever no ficheiro
		tamanho = len(dados) #Retorna o número de bytes relativos a dados que foram recebidos no pacote
		ultimo = 0
		print("Header recebido")
		print(header)
		print("Tamanho dados recebido: " + str(tamanho) + " bytes")
		y = SHA256.new(dados) #É criado um checksum
		t = y.hexdigest()[:4] 
		q = t.encode()
		checksum = int(q,16) #Converte o checksum para base 10
		socket.settimeout(.01)
		while(dados):
			try:
				if (header.num_seq == ultimo) and (checksum == header.checksum): #Se o pacote recebido for o esperado e o checksum for validado, os dados são guardados no ficheiro na sua respetiva posição
					ultimo = ultimo + tamanho
					f.seek(seek,0)
					f.write(dados)
					if tamanho !=1024:
						break
				data,ipC = socket.recvfrom(1500)
				header = others.desconverte(data)
				dados = others.getData(data)
				seek = header.num_seq
				tamanho = len(dados)
				print("Header recebido")
				print(header)
				print("Tamanho dados recebido: " + str(tamanho) + " bytes")
				y= SHA256.new(dados) #cria um checksum
				t = y.hexdigest()[:4]
				q = t.encode()
				checksum = int(q,16) #converte para base 10
			except timeout: #Janela de envio concluída, enviamos PDU com a posição onde as coisas podem ter começado a correr mal
				pdu = others.Header(ultimo,0,0,0,0,0,1,0)
				x = pdu.converte()
				print("Header com posição de envio")
				print(pdu)
				socket.sendto(x,(ipC[0],portC))
				time.sleep(0.01)
		
		print("\nDownload do ficheiro concluído\n")
		f.close() #Fecha o file descriptor
		estado = Estado.FIN_R #Entramos na fase do término de ligação

	elif estado == Estado.FIN_R:
		try:
			while True:
				socket.settimeout(1)
				dados, ipC = socket.recvfrom(512)
				z = others.desconverte(dados)
				if z.fin == 1:
					checkNumber = random.randint(0, (2**12)-2)
					num_seq = checkNumber
					num_ack = z.num_seq + 1
					checksum = 0
					syn = 0
					psh = 0
					rst = 0
					ack = 1
					fin = 1
					pf2 = others.Header(num_seq,num_ack,checksum,syn,psh,rst,ack,fin)
					print("FIN do servidor para o cliente - PF2")
					print(pf2)
					x = pf2.converte()
					socket.sendto(x,(ipC[0],portC)) #Envia fin para o cliente
					print("PF2 enviado")
					print("\n")
					dados, ipC = socket.recvfrom(512) #Espera pelo ack do cliente
					zz = others.desconverte(dados)
					if zz.ack == 1:
						socket.close()
						print("Bye-Bye")
						break
			break

		except timeout:
			estado = Estado.FECHADO
			print("Não foi recebido um fin do cliente, a reenviar PF2")
			socket.sendto(x,(ipC[0],portC)) #Envia fin para o cliente
			contador2 = contador2 + 1
			if(contador2 == 10): #Reenvia o fin ao cliente
				socket.close()
				break
				print("Não foi recebido um fin do cliente, a encerrar socket, bye-bye")