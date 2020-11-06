package models

import (
	"regexp"
	"strings"

	"priva-web/hash"
	"priva-web/rand"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// Change and relocate as an environment variable for production.
const (
	userPwPepper  = "rOPLsik9dQbBnlNBeXfs"
	hmacSecretKey = "VW5rivKgsnMV"
)

// Because we made the underlying type of our modelError
// a string we can define these as constants instead of variables.
const (
	//	GENERAL ERRORS:
	//
	//	ErrNotFound is returned when a resource cannot be found
	//	in the database.
	ErrNotFound modelError = "models: resource not found."
	//	ErrIDInvalid is returned when an invalid ID is provided
	//	to a method like Delete.
	ErrIDInvalid modelError = "model: ID provided was invalid."

	//	REMEMBER ERRORS:
	//
	//	ErrRememberRequired is returned when a create or update
	//	is attempted without a user remember token hash.
	ErrRememberRequired modelError = "model: Remember token is required."
	//	ErrRememberTooShort is returned when a remember token is
	//	not at least 32 bytes.
	ErrRememberTooShort modelError = "model: Remember token must be at least 32 bytes."

	//	EMAIL ERRORS:
	//
	//	ErrEmailRequired is returned when an email address is not
	//	provided when creating a user.
	ErrEmailRequired modelError = "models: Email address is required."
	//	ErrEmailInvalid is returned when an email address provided
	//	does not match any of our requirements.
	ErrEmailInvalid modelError = "models: Email address is invalid."
	// 	ErrEmailTaken is returned when an update or create is attempted
	// 	with an email address that is already in use.
	ErrEmailTaken modelError = "models: Email address is already taken."

	//	USERNAME ERRORS:
	//
	//	ErrUsernameRequired is returned when a username is not 
	//	provided when creating a user.
	ErrUsernameRequired modelError = "models: Username is required."
	//	ErrEmailInvalid is returned when an email address provided
	//	does not match any of our requirements.
	ErrUsernameInvalid modelError = "models: Username is invalid."
	// 	ErrEmailTaken is returned when an update or create is attempted
	// 	with an email address that is already in use.
	ErrUsernameTaken modelError = "models: Username is already taken."
	
	//	PASSWORD ERRORS:
	//
	//	ErrPasswordIncorrect is return when an invalid password
	//	is used when attempting to authenticate a user.
	ErrPasswordIncorrect modelError = "models: Incorrect password provided."
	//	ErrPasswordTooShort is returned when auser tries to set
	//	a password that is less than 8 characters long.
	ErrPasswordTooShort modelError = "models: Password must be at least 8 characters long."
	// 	ErrPasswordRequired is returned when a create is attempted
	//	without a user password provided.
	ErrPasswordRequired modelError = "models: Password is required."
)

// Set this variable’s type to UserDB, and then assign a pointer
// to a userGorm as the value. Assuming our userGorm implements the
// UserDB interface, this code will compile correctly. If the
// userGorm does not implement the UserDB interface,
// we will get an error when we try to compile our code.
var _ UserDB = &userGorm{}

// Verify that our userService type implements the UserService interface.
var _ UserService = &userService{}

// User is used to represent the data we store in our database.
// It doesn’t have methods attached to it, and is instead
// passed into other functions and methods.
type User struct {
	gorm.Model
	Username     string `gorm:"not null;unique_index"`
	Email        string `gorm:"not null;unique_index"`
	Password     string `gorm:"-"`
	PasswordHash string `gorm:"not null"`
	Remember     string `gorm:"-"`
	RememberHash string `gorm:"not null;unique_index"`
	// 	Addresses
	// 	Connections
	// 	Orders
	// 	Referrer
	UUID uuid.UUID `gorm:"primary_key; unique; 
                      	 	type:uuid; column:id; 
                         	default:uuid_generate_v4()`
}

// userService, provides us with methods to create, update,
// and otherwise interact with users. In short, this
// defines everything that can be done with a user.
type userService struct {
	UserDB
}

// UserService is a set of methods used to manipulate and
// work with the user model.
type UserService interface {
	// 	Authenticate will verify the provided email address and password
	// 	are correct. If they are correct, the user corresponding to that
	// 	email will be returned. Otherwise you will receive either:
	//	ErrNotFound, ErrPasswordIncorrect, or another error if something goes wrong.
	Authenticate(email, password string) (*User, error)
	UserDB
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

/*
//////////////////////////////////////////////////////////
Public Errors - ATTN: Relocate to it's own package.
//////////////////////////////////////////////////////////
*/

type modelError string

func (e modelError) Error() string {
	return string(e)
}

func (e modelError) Public() string {
	s := strings.Replace(string(e), "models: ", "", 1)
	// Split our string into a slice of strings
	// everywhere there is a space using the Split function.
	split := strings.Split(s, " ")
	// Access only the first word of the message
	// and pass it into the Title function to capitalize it.
	split[0] = strings.Title(split[0])
	// Update its value in the slice of strings
	// then use the Join function11 to merge all
	// of these strings back together reinserting
	// the original spaces.
	return strings.Join(split, " ")
}

/*
//////////////////////////////////////////////////////////
VALIDATION / NORMALIZATION LAYER
//////////////////////////////////////////////////////////
*/

// userValidator is our validation layer that
// validates and normalizes data before passing
// it on to the next UserDB in our interface chain.
type userValidator struct {
	UserDB
	hmac hash.HMAC
	//	We are going to need acccess to our regular expressions
	//	from our userValidator methods, so rather than create
	//	global variables we will use fields on this type.
	emailRegex *regexp.Regexp
	usernameRegex *regexp.Regexp
}

// newUserValidator constructs our userValidator.
func newUserValidator(udb UserDB, hmac hash.HMAC) *userValidator {
	return &userValidator{
		UserDB: udb,
		hmac:   hmac,
		emailRegex: regexp.MustCompile(
			`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,16}$`),
		usernameRegex: regexp.MustCompile(
			`^[A-Za-z0-9]{2,32}$`),
	}
}

// A function type named userValFn that defines what
// we expect a user validation function to look like.
type userValFn func(*User) error

// The runUserValFns function accepts a pointer to a
// user and any number of validation functions as
// its arguments, and then it iterates over each
// validation function using a range. As it iterates
// over each function, it calls that validation function
// passing in the user as the argument, and capturing
// the error return value.
func runUserValFns(user *User, fns ...userValFn) error {
	for _, fn := range fns {
		if err := fn(user); err != nil {
			return err
		}
	}
	return nil
}

// func (uv *userValidator) ByID(id uint) (*User, error) {
// // 	Validate the ID
// 	if id <= 0 {
// 		return nil, errors.New("Invalid ID")
// 	}
// // 	If the ID is valid, call the next method in the chain and return it's results
// 	return uv.UserDB.ByID(id), nil
// }

// Authenticate can be used to authenticate a user with the
// provided email address and password.
// If the email address provided is invalid,
// this will return nil, ErrNotFound.
// If the password provided is invalid,
// nil, ErrPasswordIncorrect.
// If the email and password are both valid, this will return
// user, nil
// Otherwise if another error is encountered, this will return
// nil, error
func (us *userService) Authenticate(email, password string) (*User, error) {
	// Lookup the user with provided email address.
	foundUser, err := us.ByEmail(email)
	if err != nil {
		return nil, err
	}
	// Check provided password is valid and store in err.
	err = bcrypt.CompareHashAndPassword(
		[]byte(foundUser.PasswordHash),
		[]byte(password+userPwPepper))
	// Check err to determine result.
	switch err {
	case nil:
		return foundUser, nil
	case bcrypt.ErrMismatchedHashAndPassword:
		return nil, ErrPasswordIncorrect
	default:
		return nil, err
	}
}

// Create will create the provided user and backfill data
// like the ID, CreatedAt, and UpdatedAt fields.
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
		uv.emailIsAvail,
		uv.normalizeUsername,
		uv.requireUsername,
		uv.usernameFormat,
		uv.usernameIsAvail)
	if err != nil {
		return err
	}
	return uv.UserDB.Create(user)
}

// Update
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
		uv.emailIsAvail,
		uv.normalizeUsername,
		uv.requireUsername,
		uv.usernameFormat,
		uv.usernameIsAvail)
	if err != nil {
		return err
	}
	return uv.UserDB.Update(user)
}

// Delete
func (uv *userValidator) Delete(id uint) error {
	var user User
	user.ID = id
	err := runUserValFns(&user, uv.idGreaterThan(0))
	if err != nil {
		return err
	}
	return uv.UserDB.Delete(id)
}

// ByRemember will hash the remember token and then call
// ByRemember on the subsequent UserDB layer. Since hashing is
// a form of normalization, we will include it on the validation layer.
// We create a user, set the token to the Remember field,
// and then use the RememberHash that gets set by the hmacRemember normalizer.
// This is how we get around the fact that our ByRemember method
// doesn’t have a User object passed in even though our
// validation functions require one.
func (uv *userValidator) ByRemember(token string) (*User, error) {
	// Create a user variable and set the Remember
	// field to the token we want normalized.
	user := User{
		Remember: token,
	}
	// Our normalizer will then set the RememberHash field
	// on the user we created, allowing us to pass that
	// into the next layer as the hashed token.
	if err := runUserValFns(&user, uv.hmacRemember); err != nil {
		return nil, err
	}
	return uv.UserDB.ByRemember(user.RememberHash)
}

// ByEmail will normalize an email address before passing
// it on to the database layer to perform the query.
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

// ByUsername will normalize an username before passing
// it on to the database layer to perform the query.
func (uv *userValidator) ByUsername(username string) (*User, error) {
	user := User{
		Username: username,
	}
	err := runUserValFns(&user, uv.normalizeUsername)
	if err != nil {
		return nil, err
	}
	return uv.UserDB.ByUsername(user.Username)
}

// hmacRemember validation function.
func (uv *userValidator) hmacRemember(user *User) error {
	if user.Remember == "" {
		return nil
	}
	user.RememberHash = uv.hmac.Hash(user.Remember)
	return nil
}

// setRememberIfUnset will verify a remember token
// is given a default value if none exists. We can
// not save users in the database without a remember token.
func (uv *userValidator) setRememberIfUnset(user *User) error {
	// Check if user's remember token is set.
	if user.Remember != "" {
		return nil
	}
	// Generate a remember token using the rand package.
	token, err := rand.RememberToken()
	if err != nil {
		return err
	}
	// Set the new remember token on the user.
	user.Remember = token
	return nil
}

// rememberMinBytes func
func (uv *userValidator) rememberMinBytes(user *User) error {
	if user.Remember == "" {
		return nil
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

// rememberHashRequired func
func (uv *userValidator) rememberHashRequired(user *User) error {
	if user.RememberHash == "" {
		return ErrRememberRequired
	}
	return nil
}

// normalizeEmail function
func (uv *userValidator) normalizeEmail(user *User) error {
	user.Email = strings.ToLower(user.Email)
	user.Email = strings.TrimSpace(user.Email)
	return nil
}

// requireEmail function
func (uv *userValidator) requireEmail(user *User) error {
	if user.Email == "" {
		return ErrEmailRequired
	}
	return nil
}

// emailFormat function uses a MatchString method which
// will return true if a string matches our regex pattern
// created on our constructed userValidator within the
// newUserValidator function.
func (uv *userValidator) emailFormat(user *User) error {
	// 	Check if email is present so this validation can
	// 	be used in situations where an email address isn’t required.
	// 	We have a validation that requires an email address which
	//  will catch this case and return a more specific and helpful error.
	if user.Email == "" {
		return nil
	}
	// 	Check if email matches our regex pattern.
	if !uv.emailRegex.MatchString(user.Email) {
		return ErrEmailInvalid
	}
	return nil
}

// emailIsAvail function
func (uv *userValidator) emailIsAvail(user *User) error {
	existing, err := uv.ByEmail(user.Email)
	if err == ErrNotFound {
		// 	Email address is available if we don't find
		// 	a user with that email address.
		return nil
	}
	//	We can't continue our validation without
	//	a successful query, so if we get any error other
	//  than ErrNotFound we should return it.
	if err != nil {
		return err
	}
	// If we get here that means we found a user w/ this email
	// address, so we need to see if this is the same user we
	// are updating, or if we have a conflict.
	if user.ID != existing.ID {
		return ErrEmailTaken
	}
	return nil
}

// normalizeUsername function
func (uv *userValidator) normalizeUsername(user *User) error {
	user.Username = strings.ToUpper(user.Username)
	user.Username = strings.TrimSpace(user.Username)
	return nil
}

// requireUsername function
func (uv *userValidator) requireUsername(user *User) error {
	if user.Username == "" {
		return ErrUsernameRequired
	}
	return nil
}

// usernameFormat function uses a MatchString method which
// will return true if a string matches our regex pattern
// created on our constructed userValidator within the
// newUserValidator function.
func (uv *userValidator) usernameFormat(user *User) error {
	// 	Check if username is present so this validation can
	// 	be used in situations where an username isn’t required.
	// 	We have a validation that requires an username which
	//  will catch this case and return a more specific and helpful error.
	if user.Username == "" {
		return nil
	}
	// 	Check if email matches our regex pattern.
	if !uv.usernameRegex.MatchString(user.Username) {
		return ErrUsernameInvalid
	}
	return nil
}

// usernameIsAvail function
func (uv *userValidator) usernameIsAvail(user *User) error {
	existing, err := uv.ByUsername(user.Username)
	if err == ErrNotFound {
		// 	Username is available if we don't find
		// 	a user with that username.
		return nil
	}
	//	We can't continue our validation without
	//	a successful query, so if we get any error other
	//  than ErrNotFound we should return it.
	if err != nil {
		return err
	}
	// If we get here that means we found a user w/ this username
	// , so we need to see if this is the same user we
	// are updating, or if we have a conflict.
	if user.ID != existing.ID {
		return ErrUsernameTaken
	}
	return nil
	
}

// bcryptPassword will hash a user's password with an
// app-wide pepper and bcrypt, which salts for us.
func (uv *userValidator) bcryptPassword(user *User) error {
	// Check if password field is empty. If not,
	// the new password needs to be hashed.
	if user.Password == "" {
		return nil
	}
	// Pepper the password before hashing
	pwBytes := []byte(user.Password + userPwPepper)
	// Hash the password. Bcrypt handles salting automaticallly.
	hashedBytes, err := bcrypt.GenerateFromPassword(
		pwBytes, bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	// Set user's PasswordHash field to the converted hashedBytes string.
	user.PasswordHash = string(hashedBytes)
	// Set user's Password field to an empty string, as we do
	// not store passwords in the database.
	user.Password = ""
	return nil
}

// passwordMinLength func
func (uv *userValidator) passwordMinLength(user *User) error {
	// Check if password is present.
	if user.Password == "" {
		return nil
	}
	// Check length of password is 8 or more characters.
	if len(user.Password) < 8 {
		return ErrPasswordTooShort
	}
	return nil
}

// passwordRequired func
func (uv *userValidator) passwordRequired(user *User) error {
	if user.Password == "" {
		return ErrPasswordRequired
	}
	return nil
}

// passwordHashRequired func
func (uv *userValidator) passwordHashRequired(user *User) error {
	if user.PasswordHash == "" {
		return ErrPasswordRequired
	}
	return nil
}

// idGreaterThan function is to make sure any user IDs
// provided are greater than n. This is not a validation function,
// instead it returns a validation function when we call it
// with an unsigned integer.
func (uv *userValidator) idGreaterThan(n uint) userValFn {
	// Return a function that matches the userValFn definition
	// (i.e must accept a pointer to a user and return an error).
	return userValFn(func(user *User) error {
		if user.ID <= n {
			return ErrIDInvalid
		}
		return nil
	})
}

// idLessThan function is to make sure any user IDs
// provided are less than n. This is not a validation function,
// instead it returns a validation function when we call it
// with an unsigned integer.
func (uv *userValidator) idLessThan(n uint) userValFn {
	// Return a function that matches the userValFn definition
	// (i.e must accept a pointer to a user and return an error).
	return userValFn(func(user *User) error {
		if user.ID >= n {
			return ErrIDInvalid
		}
		return nil
	})
}

/*
//////////////////////////////////////////////////////////
DATABASE LAYER
//////////////////////////////////////////////////////////
*/

// userGorm represents our database interaction layer
// and implements the UserDB interface fully.
type userGorm struct {
	db *gorm.DB
}

// UserDB is used to interact with the users database.
//
// Most single user queries:
// If the user is found, we will return a nil error
// If the user is not found, we will return ErrNotFound
// If there is another error, we will return an error with
// more information about what went wrong. This may not be
// an error generated by the models package.
//
// For single user queries, any error but ErrNotFound should
// probably result in a 500 error until we make "public"
// facing errors.
type UserDB interface {
	// 	Methods for querying for single users.
	ByID(id uint) (*User, error)
	ByEmail(email string) (*User, error)
	ByUsername(username string) (*User, error)
	ByRemember(token string) (*User, error)

	// 	Methods for altering users.
	Create(user *User) error
	Update(user *User) error
	Delete(id uint) error

	//	Close a DB connection
	Close() error

	// 	Migration helpers
	AutoMigrate() error
	DestructiveReset() error
}

// newUserGorm
func newUserGorm(connectionInfo string) (*userGorm, error) {
	// Open connection to DB.
	db, err := gorm.Open("postgres", connectionInfo)
	if err != nil {
		return nil, err
	}
	// Enable DB logging for debugging
	db.LogMode(true)
	// Return pointer to userGorm object.
	return &userGorm{
		db: db,
	}, nil
}

// Create will create the provided user and
// backfill data like ID, CreatedAd, and UpdatedAt.
func (ug *userGorm) Create(user *User) error {
	// Create the user.
	return ug.db.Create(user).Error
}

// Update will update the provided user with all of the data
// in the provided user object.
func (ug *userGorm) Update(user *User) error {
	return ug.db.Save(user).Error
}

// Delete will delete the user with the provided ID.
func (ug *userGorm) Delete(id uint) error {
	user := User{Model: gorm.Model{ID: id}}
	return ug.db.Delete(&user).Error
}

// ByRemember looks up a user with the given remember token
// and returns that user. This method expects the remember
// token to already be hashed.
// Errors are the same as ByEmail.
func (ug *userGorm) ByRemember(rememberHash string) (*User, error) {
	var user User
	err := first(ug.db.Where("remember_hash = ?", rememberHash), &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ByID will look up a user with the provided ID.
// If the user is found, we will return a nil error
// If the user is not found, we will return ErrNotFound
// If there is another error, we will return an error with
// more information about what went wrong. This may not be
// an error generated by the models package.
//
// As a general rule, any error but ErrNotFound should
// probably result in a 500 error.
func (ug *userGorm) ByID(id uint) (*User, error) {
	var user User
	db := ug.db.Where("id = ?", id)
	err := first(db, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ByEmail looks up a user with the given email address and
// returns that user.
// If the user is found, we will return a nil error
// If the user is not found, we will return ErrNotFound
// If there is another error, we will return an error with
// more information about what went wrong. This may not be
// an error generated by the models package.
func (ug *userGorm) ByEmail(email string) (*User, error) {
	var user User
	db := ug.db.Where("email = ?", email)
	err := first(db, &user)
	return &user, err
}
  
// ByUsername looks up a user with the given username and
// returns that user.
// If the user is found, we will return a nil error
// If the user is not found, we will return ErrNotFound
// If there is another error, we will return an error with
// more information about what went wrong. This may not be
// an error generated by the models package.
func (ug *userGorm) ByUsername(username string) (*User, error) {
	var user User
	db := ug.db.Where("username = ?", username)
	err := first(db, &user)
	return &user, err
}
   


/*
//////////////////////////////////////////////////////////
Database Queries / Helpers
//////////////////////////////////////////////////////////
*/

// first will query using the provided gorm.DB and it will
// get the first item returned and place it into dst. If
// nothing is found in the query, it will return ErrNotFound
//
// Query: SELECT * FROM users ORDER BY id LIMIT 1;
func first(db *gorm.DB, dst interface{}) error {
	err := db.First(dst).Error
	if err == gorm.ErrRecordNotFound {
		return ErrNotFound
	}
	return err
}

// last will query using the provided gorm.DB and it will
// get the last item returned and place it into dst. If
// nothing is found in the query, it will return ErrNotFound
//
// Query: SELECT * FROM users ORDER BY id DESC LIMIT 1;
func last(db *gorm.DB, dst interface{}) error {
	err := db.Last(dst).Error
	if err == gorm.ErrRecordNotFound {
		return ErrNotFound
	}
	return err
}

// all will query using the provided gorm.DB and it will
// get all items returned and place it into dst. If
// nothing is found in the query, it will return ErrNotFound
//
// Query: SELECT * FROM users;
func all(db *gorm.DB, dst interface{}) error {
	err := db.Find(dst).Error
	if err == gorm.ErrRecordNotFound {
		return ErrNotFound
	}
	return err
}

// Closes the UserService database connection.
func (ug *userGorm) Close() error {
	return ug.db.Close()
}

// AutoMigrate will attempt to automaticallly
// migrate the users table.
func (ug *userGorm) AutoMigrate() error {
	if err := ug.db.AutoMigrate(&User{}).Error; err != nil {
		return err
	}
	return nil
}

// DestructiveReset drops the user table and rebuilds it.
// *Remove for production.
func (ug *userGorm) DestructiveReset() error {
	err := ug.db.DropTableIfExists(&User{}).Error
	if err != nil {
		return err
	}
	return ug.AutoMigrate()
}
