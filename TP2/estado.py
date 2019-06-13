#Define as tabelas informativas sobre as transferências
#python3
from texttable import Texttable

#Define classe Tabela
class Tabela:
	#método constructor
	def __init__(self,nome,tamanho,ip_destino,porta_origem,porta_destino):
		self.t = Texttable()
		self.tt = self.t.set_cols_align(["c", "c", "c", "c", "c"])
		self.ttt = self.t.set_cols_valign(["m", "m", "m", "m", "m"])
		self.tabela = self.tt.add_rows([['Nome_Ficheiro','Tamanho\n(em bytes)','IP_Destino','Porta_Origem','Porta_Destino'], [nome,tamanho,ip_destino,porta_origem,porta_destino]])

	#método toString
	def __str__(self):
		return print(self)

#método que imprime a tabela
def print(x):
	return(x.tabela.draw())