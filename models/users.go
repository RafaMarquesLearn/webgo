package models

import (
	"github.com/RafaMarquesLearn/webgo/hash"
	"github.com/RafaMarquesLearn/webgo/rand"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"
	"regexp"
	"strings"
)

const (
	hmacSecretKey = "goisawesome"
	userPwPepper  = "golangisawesome"
)

var (
	// Esse erro é retornado quando um recurso(objeto) não puder ser encontrado no banco de dados.
	ErrNotFound modelError = "models: A busca não encontrou nenhum resultado!"

	// Esse erro é retornado quando um ID inválido for passado.
	ErrIdInvalid modelError = "models: O ID fornecido não é valido!"

	// Esse erro é retornado quando o usuário tenta cadastrar com uma senha vazia.
	ErrPasswordRequired modelError = "models: A senha é obrigatória!"

	// Esse erro é retornado quando uma senha inválida for usada para tentar autenticar um usuário.
	ErrPasswordInvalid modelError = "models: A senha informada está incorreta!"

	// Esse erro é retornado quando o usuário tenta cadastrar uma senha menor que 8 dígitos.
	ErrPasswordTooShort modelError = "models: A senha precisa ter pelo menos 8 caracteres!"

	// Esse erro é retornado quando o email não é informado na criação ou atualização do usuário.
	ErrEmailRequired modelError = "models: O email é obrigatório!"

	// Esse erro é retornado quando o email informado na criação ou atualização do usuário não bate com o padrão.
	ErrEmailInvalid modelError = "models: O email não é válido!"

	// Esse erro é retornado quando o email informado na criação ou atualização do usuário já está em uso.
	ErrEmailTaken modelError = "models: O email já está em uso!"

	// Esse erro é retornado quando não há um 'token remember hash' na criação ou atualização do usuário.
	ErrRememberRequired modelError = "models: O token é obrigatório!"

	// Esse erro é retornado quando um 'token remember' não tem pelo menos 32 bytes.
	ErrRememberTooShort modelError = "models: O token precisa ter pelo menos 32 bytes!"

	// As duas variáveis abaixo servem apenas como 'teste': são nomeadas '_' porque não serão usadas,
	// existem apenas para verificar se os ponteiros aos quais foram atribuídas implementam as interfaces de seus
	// respectivos tipos.
	_ UserDB      = &userGorm{}
	_ UserService = &userService{}
)

// Representa os dados relacionados aos usuários que serão armazenados no banco de dados.
type User struct {
	gorm.Model
	Name         string
	Email        string `gorm:"not null;unique_index"`
	Password     string `gorm:"-"`
	PasswordHash string `gorm:"not null"`
	Remember     string `gorm:"-"`
	RememberHash string `gorm:"not null;unique_index"`
}

// userGorm representa nossa camada de interação com o banco de dados e implementa completamente a interface UserDB
type userGorm struct {
	db *gorm.DB
}

// Representa métodos para interagir com os dados dos usuários, funções de banco de dados e criptografia
type userService struct {
	UserDB
}

// userValidator é a camada de validação e normalização de dados antes de serem passados a UserDB
type userValidator struct {
	UserDB
	hmac       hash.HMAC
	emailRegex *regexp.Regexp
}

/*
UserDB usado para interagir com o banco de dados de usuários
*/
type UserDB interface {
	// Métodos para buscar usuários únicos
	ByID(id uint) (*User, error)
	ByEmail(email string) (*User, error)
	ByRemember(token string) (*User, error)

	// Métodos para alterar usuários
	Create(user *User) error
	Update(user *User) error
	Delete(id uint) error

	// Usado para fechar a conexão com o banco de dados
	Close() error

	// Helpers para migração
	AutoMigrate() error
	DestructiveReset() error
}

/*
UserService é uma série de métodos para manipular e utilizar dados do Usuário
*/
type UserService interface {
	// Authenticate verificará se o email e senha digitados pelo usuário estão corretos.
	// Se estiverem corretos, o usuário correspondente será retornado.
	// Caso contrário, uma mensagem de erro adequada será retornada.
	Authenticate(email, password string) (*User, error)
	UserDB
}

type modelError string

/*
Authenticate é usado para um usuário utilizando um email e senha.
Se email ou senha forem inválidos, o erro respectivo será retornado.
Se outro tipo de erro for encontrado, um erro genérico será retornado.
Se tudo estiver ok, o respectivo usuário será retornado.
*/
func (us *userService) Authenticate(email, password string) (*User, error) {
	foundUser, err := us.ByEmail(email)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(foundUser.PasswordHash),
		[]byte(password+userPwPepper))
	switch err {
	case nil:
		return foundUser, nil
	case bcrypt.ErrMismatchedHashAndPassword:
		return nil, ErrPasswordInvalid
	default:
		return nil, err
	}
	return nil, nil
}

func newUserValidator(udb UserDB, hmac hash.HMAC) *userValidator {
	return &userValidator{
		UserDB:     udb,
		hmac:       hmac,
		emailRegex: regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,16}$`),
	}
}

func newUserGorm(connectionInfo string) (*userGorm, error) {
	db, err := gorm.Open("postgres", connectionInfo)
	if err != nil {
		return nil, err
	}
	db.LogMode(true)
	return &userGorm{
		db: db,
	}, nil
}

func NewUserService(connectionInfo string) (UserService, error) {
	ug, err := newUserGorm(connectionInfo)
	if err != nil {
		return nil, err
	}
	hmac := hash.NewHMAC(hmacSecretKey)
	uv := newUserValidator(ug, hmac)
	return &userService{
		UserDB: uv,
	}, nil
}

// Fecha a conexão com o banco de dados.
func (ug *userGorm) Close() error {
	return ug.db.Close()
}

/*
Create fará a validação dos dados de um novo usuário.
*/
func (uv *userValidator) Create(user *User) error {
	err := runUserValFns(user,
		uv.passwordRequired,
		uv.passwordMinLength,
		uv.bcryptPassword,
		uv.passwordHashRequired,
		uv.setRememberIfUnset,
		uv.rememberMinBytes,
		uv.hmacRemember,
		uv.rememberHashRequired,
		uv.normalizeEmail,
		uv.requireEmail,
		uv.emailFormat,
		uv.emailIsAvail)
	if err != nil {
		return err
	}

	return uv.UserDB.Create(user)
}

/*
Create fará a inserção no banco de dados de um novo usuário.
*/
func (ug *userGorm) Create(user *User) error {
	return ug.db.Create(user).Error
}

/*
Update fará a validação dos dados alterados do usuário.
*/
func (uv *userValidator) Update(user *User) error {
	err := runUserValFns(user,
		uv.passwordMinLength,
		uv.bcryptPassword,
		uv.passwordHashRequired,
		uv.rememberMinBytes,
		uv.hmacRemember,
		uv.rememberHashRequired,
		uv.normalizeEmail,
		uv.requireEmail,
		uv.emailFormat,
		uv.emailIsAvail)
	if err != nil {
		return nil
	}
	return uv.UserDB.Update(user)
}

/*
Update fará a atualização no banco de dados dos dados alterados do usuário.
*/
func (ug *userGorm) Update(user *User) error {
	return ug.db.Save(user).Error
}

/*
Delete fará a validação do ID passado.
*/
func (uv *userValidator) Delete(id uint) error {
	var user User
	user.ID = id
	err := runUserValFns(&user, uv.idGreaterThan(0))
	if err != nil {
		return err
	}
	return uv.UserDB.Delete(id)
}

/*
Delete fará a exclusão no banco de dados do usuário que tenha o ID correspondente.
*/
func (ug *userGorm) Delete(id uint) error {
	user := User{Model: gorm.Model{ID: id}}
	return ug.db.Delete(&user).Error
}

// first retorna o primeiro registro encontrado pela query. Se nada for encontrado, retorna um erro.
func first(db *gorm.DB, dst interface{}) error {
	err := db.First(dst).Error
	if err == gorm.ErrRecordNotFound {
		return ErrNotFound
	}
	return err
}

/*
ByID fará a busca por um usuário que tenha o ID correspondente.
*/
func (ug *userGorm) ByID(id uint) (*User, error) {
	var user User
	db := ug.db.Where("id = ?", id)
	err := first(db, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

/*
ByEmail vai normalizar um endereço de email antes de passá-lo para a camada de banco de dados.
*/
func (uv *userValidator) ByEmail(email string) (*User, error) {
	user := User{
		Email: email,
	}
	err := runUserValFns(&user, uv.normalizeEmail)
	if err != nil {
		return nil, err
	}
	return uv.UserDB.ByEmail(user.Email)
}

/*
ByEmail fará a busca por um usuário que tenha o email correspondente.
*/
func (ug *userGorm) ByEmail(email string) (*User, error) {
	var user User
	db := ug.db.Where("email = ?", email)
	err := first(db, &user)
	return &user, err
}

/*
ByRemember fará a busca por um usuário que tenha o 'token remember' correspondente.
*/
func (uv *userValidator) ByRemember(token string) (*User, error) {
	user := User{
		Remember: token,
	}

	if err := runUserValFns(&user, uv.hmacRemember); err != nil {
		return nil, err
	}
	return uv.UserDB.ByRemember(user.RememberHash)
}

/*
ByRemember fará a busca por um usuário que tenha o 'token remember' correspondente.
*/
func (ug *userGorm) ByRemember(rememberHash string) (*User, error) {
	var user User
	err := first(ug.db.Where("remember_hash = ?", rememberHash), &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

/*
DestructiveReset destrói a tabela de usuários e depois chama o método AutoMigrate para reconstruí-la.
*/
func (ug *userGorm) DestructiveReset() error {
	err := ug.db.DropTableIfExists(&User{}).Error
	if err != nil {
		return err
	}
	return ug.AutoMigrate()
}

/*
AutoMigrate faz a migração automática da tabela de usuários no banco de dados.
*/
func (ug *userGorm) AutoMigrate() error {
	if err := ug.db.AutoMigrate(&User{}).Error; err != nil {
		return err
	}
	return nil
}

func runUserValFns(user *User, fns ...userValFn) error {
	for _, fn := range fns {
		if err := fn(user); err != nil {
			return err
		}
	}
	return nil
}

type userValFn func(*User) error

func (uv *userValidator) bcryptPassword(user *User) error {
	if user.Password == "" {
		return nil
	}
	pwBytes := []byte(user.Password + userPwPepper)
	hashedBytes, err := bcrypt.GenerateFromPassword(pwBytes, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.PasswordHash = string(hashedBytes)
	user.Password = ""
	return nil
}

func (uv *userValidator) hmacRemember(user *User) error {
	if user.Remember == "" {
		return nil
	}
	user.RememberHash = uv.hmac.Hash(user.Remember)
	return nil
}

func (uv *userValidator) setRememberIfUnset(user *User) error {
	if user.Remember != "" {
		return nil
	}
	token, err := rand.RememberToken()
	if err != nil {
		return err
	}
	user.Remember = token
	return nil
}

func (uv *userValidator) idGreaterThan(n uint) userValFn {
	return userValFn(func(user *User) error {
		if user.ID <= n {
			return ErrIdInvalid
		}
		return nil
	})
}

func (uv *userValidator) normalizeEmail(user *User) error {
	user.Email = strings.ToLower(user.Email)
	user.Email = strings.TrimSpace(user.Email)
	return nil
}

func (uv *userValidator) requireEmail(user *User) error {
	if user.Email == "" {
		return ErrEmailRequired
	}
	return nil
}

func (uv *userValidator) emailFormat(user *User) error {
	if user.Email == "" {
		return nil
	}
	if !uv.emailRegex.MatchString(user.Email) {
		return ErrEmailInvalid
	}
	return nil
}

func (uv *userValidator) emailIsAvail(user *User) error {
	existing, err := uv.ByEmail(user.Email)
	if err == ErrNotFound {
		return nil
	}
	if err != nil {
		return err
	}

	if user.ID != existing.ID {
		return ErrEmailTaken
	}
	return nil
}

func (uv *userValidator) passwordMinLength(user *User) error {
	if user.Password == "" {
		return nil
	}
	if len(user.Password) < 8 {
		return ErrPasswordTooShort
	}
	return nil
}

func (uv *userValidator) passwordRequired(user *User) error {
	if user.Password == "" {
		return ErrPasswordRequired
	}
	return nil
}

func (uv *userValidator) passwordHashRequired(user *User) error {
	if user.PasswordHash == "" {
		return ErrPasswordRequired
	}
	return nil
}

func (uv *userValidator) rememberMinBytes(user *User) error {
	if user.Remember == "" {
		return ErrPasswordRequired
	}
	n, err := rand.NBytes(user.Remember)
	if err != nil {
		return err
	}
	if n < 32 {
		return ErrRememberTooShort
	}
	return nil
}

func (uv *userValidator) rememberHashRequired(user *User) error {
	if user.RememberHash == "" {
		return ErrRememberRequired
	}
	return nil
}

func (e modelError) Error() string {
	return string(e)
}

func (e modelError) Public() string {
	s := strings.Replace(string(e), "models: ", "", 1)
	split := strings.Split(s, "")
	split[0] = strings.Title(split[0])
	return strings.Join(split, "")
}
