package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

/* Passo a fazer uso do pacote 'mux' para atuar como 'router' da aplicação.*/
func home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<h1>Bem vindo ao meu fantástico site!</h1>")
}

func contact(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "Para entrar e contato, por favor envie email "+"para <a href=\"mailto:support@rafadev.com\">"+"support@rafadev.com</a>.")
}

func faq(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<h2>Vejamos se sua dúvida já foi respondida!!</h2>")
}

func page404(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "<h1>Não podemos encontrar a página que você está tentando visitar :(</h1>"+"<p>Por favor, verfique se o endereço digitado está correto e nos envie um email se o problema persistir.</p>")
}

/* Faço uso de minha própria página '404'. */
var h http.Handler = http.HandlerFunc(page404)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", home)
	r.HandleFunc("/contact", contact)
	r.HandleFunc("/faq", faq)
	r.NotFoundHandler = h
	http.ListenAndServe(":3000", r)
}
