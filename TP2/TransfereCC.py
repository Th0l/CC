#python3
import os
import sys
import estado
from estado import Tabela

def main():
	tipo = sys.argv[1]
	if len(sys.argv) != 4:
		print("Faltam argumentos")
		print("Possíveis argumentos:")
		print("-> put ip nomeFicheiro(sem espaços)")
		print("-> get ip nomeFicheiro(sem espaços")
	else:		
		ip = sys.argv[2]
		nome = sys.argv[3]
		if tipo.upper() == "GET":
			os.system("python3 servidor.py")
			print("\nTabela Informacional")
			tamanho =os.path.getsize(nome)
			tabela = estado.Tabela(nome,tamanho,ip,9000,9999)
			print(tabela)
		elif tipo.upper() == "PUT":
			os.system("time python3 cliente.py %s %s" %(ip , nome)) 
			print("\nTabela Informacional")
			tamanho =os.path.getsize(nome)
			tabela = estado.Tabela(nome,tamanho,ip,9999,9000)
			print(tabela)

if __name__ == "__main__":
	main()
