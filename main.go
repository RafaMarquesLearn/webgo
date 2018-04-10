package main

import (
	"fmt"
	"net/http"
)

/* Função que cuida das requisições feitas ao site.
   Recebe dois argumentos, apesar de no momento não serem usados:
   1 - http.ResponseWriter, declarado como 'w', nos permite modificar a resposta que queremos enviar ao solicitante(que fez a 'request'). Podemos, por exemplo, informar a data do dia, ou o nome do usuário.
   2 - http.Request, declarado como 'r', nos permite acessar dados enviados na 'request'. Podemos, por exemplo, receber o usuário e senha depois que o usuário logar no sistema.
*/
func handlerFunc(w http.ResponseWriter, r *http.Request) {
	/* O pacote 'fmt' contém funções para formatar a exibição de mensagens ao      usuário.
	   Nesse caso, usamos a função 'Fprint'. Ela recebe dois argumentos:
	   1 - Um io.Writer, que é uma 'interface' que requer um 'struct' que tenha implementado o método 'Write([]byte), de modo que a função cuide de converter todas as 'interfaces' indicadas para um 'array de byte'. Como estamos escrevendo uma 'string', e 'strings' podem ser tratadas como 'arrays de byte', poderíamos usar 'w.Write([]byte("<h1>Bem vindo ao meu fantástico site!</h1>"))' ao invés de 'fmt.Fprint(w, "<h1>Bem vindo ao meu fantástico site!</h1>")' e obteríamos o mesmo resultado.
	   2 - Qualquer número de 'interface{}s' para exibir. Tipicamente são 'strings', mas podem ser qualquer tipo de dado.

	   INTERFACES - são uma maneira de descrever um conjunto de métodos que um objeto precisa implementar para que seja válido. Por exemplo, uma função que recebe como parâmetro "Livro" e que quando exibimos um livro, chamamos a função 'livro.Preco()' para que seja mostrado o valor do livro. Mas e se quisermos exibir um caderno? Nossa função lida apenas com livros! Ai entra a 'interface'. Ela 'não se importa' por qual tipo de objeto estamos passando, apenas que ele tenha os métodos necessários para funcionar, ou seja, os que ele implemente todos os métodos da 'interface'.
	*/
	fmt.Fprint(w, "<h1>Bem vindo ao meu fantástico site!</h1>")
}

/* Essa é a principal função de um programa Go, já que é a responsável por         fazer o programa executar. Nela chamamos métodos de outros pacotes de nossa     aplicação.
 */
func main() {
	/* Primeiro setamos nossa função 'handlerFunc' como a função que irá lidar     com as requisições feitas com o caminho '/'. Isso cobre todos os            caminhos que o usuário tente visitar, como por exemplo '/outro-caminho'.
	   Depois chamamos 'http.ListenAndServe', que inicia o servidor, ouvindo na porta 3000, usando os 'handlers' http padrão.
	*/
	http.HandleFunc("/", handlerFunc)
	http.ListenAndServe(":3000", nil)
}
