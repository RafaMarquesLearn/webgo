package views

import "log"

type Data struct {
	Alert *Alert
	Yield interface{}
}

type Alert struct {
	Level   string
	Message string
}

type PublicError interface {
	error
	Public() string
}

const (
	AlertLvlError   = "danger"
	AlertLvlWarning = "warning"
	AlertLvlInfo    = "info"
	AlertLvlSuccess = "success"
	AlertMsgGeneric = "Ocorreu um erro desconhecido. Por favor, tente novamente e contate o administrador caso o erro persista."
)

func (d *Data) SetAlert(err error) {
	var msg string
	if pErr, ok := err.(PublicError); ok {
		msg = pErr.Public()
	} else {
		log.Println(err)
		msg = AlertMsgGeneric
	}
	d.Alert = &Alert{
		Level:   AlertLvlError,
		Message: msg,
	}
}

func (d *Data) AlertError(msg string) {
	d.Alert = &Alert{
		Level:   AlertLvlError,
		Message: msg,
	}
}
