#define pdu e estados do servidor
#python 3
from enum import Enum
import random

#Estados TCP Servidor
#E corresponde a enviado
#R corresponde a recebido
class Estado(Enum):
	FECHADO = 1
	ABERTO = 2
	SYN_R = 3 
	SYN_E = 4
	ACK_R = 5
	ACK_E = 6
	SYN_ACK_R = 7
	SYN_ACK_E = 8
	FIN_R = 9
	FIN_E = 10 

class Header:
	#Método construtor
	def __init__(self, num_seq, num_ack, checksum, syn, psh, rst, ack, fin):
		self.num_seq = num_seq #numero sequencia
		self.num_ack = num_ack #numero confirmaçao
		self.checksum = checksum #checksum para controlo de erros
		self.syn = syn #flag syn - serve para iniciar comunicaçoes
		self.ack = ack #flag ack
		self.psh = psh #flag psh - serve para enviar dados
		self.rst = rst #flag rst - serve para reiniciar a comunicacao TCP
		self.fin = fin #flag fin - serve para finalizar comunicaçoes

	#Método toString
	def __str__(self):
		return print(self.converte().decode())

	#Método que converte o header para bits
	def converte(self):
		bits = '{0:032b}'.format(self.num_seq)
		bits += '{0:032b}'.format(self.num_ack)
		bits += '{0:016b}'.format(self.checksum)
		bits += '{0:01b}'.format(self.syn)
		bits += '{0:01b}'.format(self.ack)
		bits += '{0:01b}'.format(self.psh)
		bits += '{0:01b}'.format(self.rst)
		bits += '{0:01b}'.format(self.fin)
		return bits.encode()

#Método que desconverte os bits para o header em si
def desconverte(bits):
	bb = bits[:85]
	b = bb.decode()
	num_seq = int(b[:32],2)
	num_ack = int(b[32:64],2)
	checksum = int(b[64:80],2)
	syn = int(b[80],2)
	ack = int(b[81],2)
	psh = int(b[82],2)
	rst = int(b[83],2)
	fin = int(b[84],2)
	return Header(num_seq,num_ack,checksum,syn,psh,rst,ack,fin)

#Método que retorna a data do udp, comeca no bit 85 pois o header vai do 0 ate ao 84 (10,5 bytes)
#Não é necessário dar decode dos dados recebidos, pois estes serão guardados como binário
def getData(bits):
	return bits[85:]

#Método para visualizar o header do protocolo
def print(bits):
	num_seq = bits[:32]
	num_ack = bits[32:64]
	checksum = bits[64:80]
	estado = bits[80:]
	output = [num_seq+" : Número Sequência = {0}".format(int(num_seq,2))]
	output.append(num_ack+" : Número Acknowdegment = {0}".format(int(num_ack,2)))
	output.append(checksum+ " : Número Checksum = {0}".format(int(checksum,2)))
	output.append(estado+" : syn = {0}, ack = {1}, psh = {2}, rst = {3}, fin = {4}".format(estado[0], estado[1], estado[2], estado[3], estado[4]))
	return '\n'.join(output)