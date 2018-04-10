package main

import (
	"html/template"
	"os"
)

func main() {
	/* 'ParseFiles' vai abrir e tentar validar o arquivo template.
	Se estiver ok, recebemos um objeto *Template e um erro 'nil'.
	Caso contrário, recebemos um template vazio e um erro.
	*/
	t, err := template.ParseFiles("hello.gohtml")

	/* Checamos se recebemos um erro e encerramos a aplicação.*/
	if err != nil {
		panic(err)
	}

	/* Como não recebemos erro e sim um template válido, criamos uma variável do tipo struct anônimo chamada 'data', com um campo 'Name'. Logo após, instânciamos 'data', setando o valor de 'Name' com o valor 'Rafael Marques'.
	 */
	data := struct {
		Name string
	}{"Rafael Marques"}

	/* Finalmente, executamos o template, passando dois argumentos:
	1 - onde queremos escrever a saída do template('Stdout' é a janela do terminal, função fornecida pelo pacote 'os');
	2 - os dados que devem ser passados quando executarmos o template;
	*/
	err = t.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}
