package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"slices"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/lib/pq"
)

type AccountsToConnect struct {
	User_id     uuid.UUID `json:"user_id"`
	Device_code string    `json:"device_code"`
}

type Login struct {
	User     string `form:"user" json:"user" xml:"user" binding:"required"`
	Password string `form:"password" json:"password" xml:"password" binding:"required"`
}

type envConfigType struct {
	Host                   string `envconfig:"DB_HOST" default:"postgres.railway.internal"`
	Port                   int    `envconfig:"DB_PORT" default:"5432"`
	User                   string `envconfig:"DB_USER"`
	Password               string `envconfig:"DB_PASSWORD"`
	DBName                 string `envconfig:"DB_NAME"`
	SecretKey              string `envconfig:"SECRET_KEY"`
	AdminUser              string `envconfig:"ADMIN_USER"`
	AdminPass              string `envconfig:"ADMIN_PASS"`
	AcceptFriendsInMinutes int    `envconfig:"ACCEPT_FRIENDS_IN_MINUTES" default:"5"`
	RefreshTokensInMinutes int    `envconfig:"REFRESH_TOKENS_IN_MINUTES" default:"13"`
}

type AccessTokenResult struct {
	AccessToken string `json:"access_token"`
}

type DeviceResultResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	Expires_in              int    `json:"expires_in"`
}

type LoginResultResponse struct {
	AccessToken                string `json:"access_token"`
	AccessTokenExpiration      int    `json:"expires_in"`
	AccessTokenExpirationDate  string `json:"expires_at"`
	RefreshToken               string `json:"refresh_token"`
	RefreshTokenExpiration     int    `json:"refresh_expires"`
	RefreshTokenExpirationDate string `json:"refresh_expires_at"`
	AccountId                  string `json:"account_id"`
	DisplayName                string `json:"displayName"`
	InAppId                    string `json:"in_app_id"`
}

type accountIdStr struct {
	AccountId string
}

type User struct {
	ID        uuid.UUID
	Username  string
	Email     *string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type GameAccount struct {
	ID                  uuid.UUID
	DisplayName         string
	RemainingGifts      int
	PaVos               int
	AccessToken         string
	AccessTokenExp      int
	AccessTokenExpDate  time.Time
	RefreshToken        string
	RefreshTokenExp     int
	RefreshTokenExpDate time.Time
	OwnerUserID         uuid.UUID
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type Transaction struct {
	ID              uuid.UUID
	GameAccountID   uuid.UUID
	SenderName      *string
	ReceiverID      *string
	ReceiverName    *string
	ObjectStoreID   string
	ObjectStoreName string
	RegularPrice    float64
	FinalPrice      float64
	GiftImage       string
	CreatedAt       time.Time
}

var secretKey = []byte("secret-key")

// ============================ DB METHODS ============================

// ========== USER METHODS ==========
func AddUser(db *sql.DB, user User) error {
	_, err := db.Exec(`INSERT INTO users (id, username, email, password, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now())`, user.ID, user.Username, user.Email, user.Password)
	fmt.Printf("The user request value %v", user)
	if err != nil {
		fmt.Printf("Error adding user: %v", err)
	}
	return err
}

func GetUser(db *sql.DB, id uuid.UUID) (User, error) {
	var user User
	err := db.QueryRow(`SELECT id, username, email, password, created_at, updated_at FROM users WHERE id = $1`, id).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt)
	return user, err
}

func GetUserByUsername(db *sql.DB, username string) (User, error) {
	var user User
	err := db.QueryRow(`SELECT id, username, email, password, created_at, updated_at FROM users WHERE username = $1`, username).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt, &user.UpdatedAt)
	return user, err
}

func GetAllUsers(db *sql.DB) ([]User, error) {
	var users []User
	rows, err := db.Query(`SELECT id, username, email, created_at, updated_at FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func UpdateUser(db *sql.DB, user User) error {
	_, err := db.Exec(`UPDATE users SET username = $1, email = $2, password = $3, updated_at = now() WHERE id = $4`, user.Username, user.Email, user.Password, user.ID)
	return err
}

func DeleteUser(db *sql.DB, id uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM users WHERE id = $1`, id)
	return err
}

func DeleteUsersByIds(db *sql.DB, ids []uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM users WHERE id = ANY($1)`, pq.Array(ids))
	return err
}

// ========== GAME ACCOUNT METHODS ==========
func AddGameAccount(db *sql.DB, account GameAccount) error {
	_, err := db.Exec(`INSERT INTO game_accounts (id, display_name, remaining_gifts, pavos, access_token, access_token_exp, access_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date, owner_user_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), now())`, account.ID, account.DisplayName, account.RemainingGifts, account.PaVos, account.AccessToken, account.AccessTokenExp, account.AccessTokenExpDate, account.RefreshToken, account.RefreshTokenExp, account.RefreshTokenExpDate, account.OwnerUserID)
	if err != nil {
		fmt.Printf("Error adding game account: %v", err)
	}
	return err
}

func DeleteGameAccountByUsername(db *sql.DB, username string, ownerID uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM game_accounts WHERE username = $1 AND owner_user_id = $2`, username, ownerID)
	return err
}

func DeleteGameAccountByID(db *sql.DB, id uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM game_accounts WHERE id = $1`, id)
	return err
}

// get (only) the ids and refresh tokens of all game accounts in the db
// func GetAllFAccountsIds(db *sql.DB) ([]GameAccountMinimal, error) {
// 	var accounts []GameAccountMinimal
// 	rows, err := db.Query(`SELECT game_account_id, access_token, refresh_token FROM game_accounts`)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer rows.Close()
// 	for rows.Next() {
// 		var account GameAccountMinimal
// 		if err := rows.Scan(&account.GameAccountID, &account.AccessToken, &account.RefreshToken); err != nil {
// 			return nil, err
// 		}
// 		accounts = append(accounts, account)
// 	}
// 	if err := rows.Err(); err != nil {
// 		return nil, err
// 	}
// 	return accounts, nil
// }

func GetGameAccountByOwner(db *sql.DB, ownerID uuid.UUID) (GameAccount, error) {
	var account GameAccount
	err := db.QueryRow(`SELECT id, display_name, remaining_gifts, pavos, access_token, access_token_exp, access_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date FROM game_accounts WHERE owner_user_id = $1`, ownerID).Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.PaVos, &account.AccessToken, &account.AccessTokenExp, &account.AccessTokenExpDate, &account.RefreshToken, &account.RefreshTokenExp, &account.RefreshTokenExpDate)
	if err != nil {
		fmt.Printf("Error getting game account: %v", err)
		return GameAccount{}, err
	}
	return account, nil

}

func GetGameAccount(db *sql.DB, id uuid.UUID) (GameAccount, error) {
	var account GameAccount
	err := db.QueryRow(`SELECT id, display_name, remaining_gifts, pavos, access_token, access_token_exp, access_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date FROM game_accounts WHERE id = $1`, id).Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.PaVos, &account.AccessToken, &account.AccessTokenExp, &account.AccessTokenExpDate, &account.RefreshToken, &account.RefreshTokenExp, &account.RefreshTokenExpDate)
	if err != nil {
		fmt.Printf("Error getting game account: %v", err)
		return GameAccount{}, err
	}
	return account, nil
}

func UpdateGameAccount(db *sql.DB, account GameAccount) error {
	_, err := db.Exec(`UPDATE game_accounts SET display_name = $1, remaining_gifts = $2, pavos = $3, access_token = $4, access_token_exp = $5, access_token_exp_date = $6, refresh_token = $7, refresh_token_exp = $8, refresh_token_exp_date = $9 WHERE id = $10`, account.DisplayName, account.RemainingGifts, account.PaVos, account.AccessToken, account.AccessTokenExp, account.AccessTokenExpDate, account.RefreshToken, account.RefreshTokenExp, account.RefreshTokenExpDate, account.ID)
	return err
}

func DeleteGameAccount(db *sql.DB, id uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM game_accounts WHERE id = $1`, id)
	return err
}

// ========== TRANSACTION METHODS ==========
func AddTransaction(db *sql.DB, tx Transaction) error {
	_, err := db.Exec(`INSERT INTO transactions (id, game_account_id, sender_name, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())`, tx.ID, tx.GameAccountID, tx.SenderName, tx.ReceiverID, tx.ReceiverName, tx.ObjectStoreID, tx.ObjectStoreName, tx.RegularPrice, tx.FinalPrice, tx.GiftImage)
	if err != nil {
		fmt.Printf("Error adding transaction: %v", err)
	}
	return err

}

func GetTransaction(db *sql.DB, id uuid.UUID) (Transaction, error) {
	var tx Transaction
	err := db.QueryRow(`SELECT id, game_account_id, sender_name, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at FROM transactions WHERE id = $1`, id).Scan(&tx.ID, &tx.GameAccountID, &tx.SenderName, &tx.ReceiverID, &tx.ReceiverName, &tx.ObjectStoreID, &tx.ObjectStoreName, &tx.RegularPrice, &tx.FinalPrice, &tx.GiftImage, &tx.CreatedAt)
	if err != nil {
		fmt.Printf("Error getting transaction: %v", err)
		return Transaction{}, err
	}
	return tx, nil
}

func DeleteTransaction(db *sql.DB, id uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM transactions WHERE id = $1`, id)
	return err
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			return
		}

		// Should be "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer {token}"})
			return
		}

		tokenString := parts[1]

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			fmt.Println("secretKey", secretKey)
			return secretKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
			return
		}

		// Extract userID from claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["user_id"] == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		userID := claims["user_id"].(string)
		fmt.Println("userID", userID)
		// Save userID into context
		c.Set("userID", userID)

		// Continue to handler
		c.Next()
	}
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Missing authorization header")
		return
	}
	tokenString = tokenString[len("Bearer "):]

	err := verifyToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Invalid token", err.Error())
		return
	}

	fmt.Fprint(w, "Welcome to the the protected area")

}

func CreateToken(username string, userid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"user_id":  userid,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		fmt.Println("Error signing token:", err)
		return "", nil
	}
	return tokenString, nil
}

func CreateAdminToken(username string, userid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"user_id":  userid,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
			"admin":    true,
		})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", nil
	}
	return tokenString, nil
}

func VerifyAdminToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		return err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["admin"] == true {
			return nil
		}
	}
	return fmt.Errorf("invalid admin token")
}

func verifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

func protectedEndpointHandler(c *gin.Context) int {
	err := verifyToken(c.Request.Header.Get("Authorization")[len("Bearer "):])
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
		return 401
	}
	return 200 // 200 OK
}

func adminProtectedEndpointHandler(c *gin.Context) int {

	err := verifyToken(c.Request.Header.Get("Authorization")[len("Bearer "):])
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
		return 401
	}
	return 200 // 200 OK
}

// func GetEpicFriendsState(accessToken string, accountId string) ([]string, []string, error) {
// 	client := &http.Client{Timeout: 10 * time.Second}

// 	// Get incoming friend requests
// 	req1, _ := http.NewRequest("GET", fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/incoming", accountId), nil)
// 	req1.Header.Set("Authorization", "bearer "+accessToken)
// 	resp1, err := client.Do(req1)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	defer resp1.Body.Close()

// 	var incoming []accountIdStr
// 	if err := json.NewDecoder(resp1.Body).Decode(&incoming); err != nil {
// 		return nil, nil, err
// 	}

// 	// Get existing friends
// 	req2, _ := http.NewRequest("GET", fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/friends", accountId), nil)
// 	req2.Header.Set("Authorization", "bearer "+accessToken)
// 	resp2, err := client.Do(req2)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	defer resp2.Body.Close()

// 	var friends []accountIdStr
// 	if err := json.NewDecoder(resp2.Body).Decode(&friends); err != nil {
// 		return nil, nil, err
// 	}

// 	// Collect IDs
// 	var incomingIDs []string
// 	for _, f := range incoming {
// 		incomingIDs = append(incomingIDs, f.AccountId)
// 	}
// 	var friendsIDs []string
// 	for _, f := range friends {
// 		friendsIDs = append(friendsIDs, f.AccountId)
// 	}

// 	return incomingIDs, friendsIDs, nil
// }

// ============================ AUTH HANDLERS ============================
func HandlerLoginForm(db *sql.DB, adminUsername string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var form Login
		if err := c.ShouldBind(&form); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		//Get user from db
		dbuser, err := GetUserByUsername(db, form.User)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials", "details": err.Error()})
			return
		}
		if dbuser.Password == form.Password {
			//todo pick admin username from somewhre else. secret source.
			if dbuser.Username == adminUsername {
				tokenString, err := CreateAdminToken(dbuser.Username, dbuser.ID.String())
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token", "details": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": tokenString})
				return
			} else {
				tokenString, err := CreateToken(dbuser.Username, dbuser.ID.String())
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token", "details": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": tokenString})
				return
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Password"})

	}
}

// ============================ USER HANDLERS ============================

func HandlerAddNewUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := adminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		var newUser User
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if newUser.ID == uuid.Nil {
			newUser.ID = uuid.New()
		}
		newUser.CreatedAt = time.Now()
		newUser.UpdatedAt = time.Now()
		if err := AddUser(db, newUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not add new user", "details": err.Error()})
			return
		}
		c.String(http.StatusOK, "User added successfully")
	}
}

func HandlerGetAllUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := adminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		users, err := GetAllUsers(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch users", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, users)
	}
}

func HandlerRemoveUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := adminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		//block deletion of admin account
		adminUser, err := GetUserByUsername(db, os.Getenv("ADMIN_USER"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch admin user", "details": err.Error()})
			return
		}
		if adminUser.ID == uuid.Nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Admin user not found"})
			return
		}

		var ids []uuid.UUID
		if err := c.ShouldBindJSON(&ids); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Check if any of the IDs are the admin user ID
		if slices.Contains(ids, adminUser.ID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete admin user"})
			return
		}

		errr := DeleteUsersByIds(db, ids)
		if errr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not remove users", "details": errr.Error()})
			return
		}
		c.String(http.StatusOK, "Users removed successfully")
	}
}

func HandlerUpdateUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := adminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		var updates map[string]interface{}
		if err := c.ShouldBindJSON(&updates); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		idStr, ok := updates["id"].(string)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
			return
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format", "details": err.Error()})
			return
		}
		delete(updates, "id")
		if len(updates) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
			return
		}
		setParts := []string{}
		args := []interface{}{}
		argIdx := 1
		for key, value := range updates {
			setParts = append(setParts, fmt.Sprintf("%s = $%d", key, argIdx))
			args = append(args, value)
			argIdx++
		}
		setParts = append(setParts, fmt.Sprintf("updated_at = $%d", argIdx))
		args = append(args, time.Now())
		query := fmt.Sprintf(`UPDATE users SET %s WHERE id = $%d`, strings.Join(setParts, ", "), argIdx+1)
		args = append(args, id)
		_, err = db.Exec(query, args...)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update user", "details": err.Error()})
			return
		}
		c.String(http.StatusOK, "User updated successfully")
	}
}

// ============================ FORTNITE ACCOUNT HANDLERS ============================
func HandlerDisconnectFAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := protectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req struct {
			Id string `json:"id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := DeleteGameAccountByID(db, uuid.MustParse(req.Id))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not disconnect Fortnite account", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Fortnite account disconnected successfully"})
	}
}

// ============================ MAIN ============================
func main() {
	// Load environment variables from .env file

	//first check if the file exists and then load it
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			log.Fatalf("Error loading .env file: %v", err)
		}
	}
	// Process environment variables into Config struct
	var cfg envConfigType
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("Error processing environment variables: %v", err)
	}

	// Construct the PostgreSQL connection string
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		fmt.Printf("Error connecting to the database: %v", err)
		panic(err)
	}

	var refreshTokenList RefreshList = make(RefreshList)

	router := gin.Default()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	allowedOrigins := map[string]bool{
		"*":                                true,
		"http://localhost:5173":            true,
		"https://your-production-site.com": true,
		"chrome-extension://gmmkjpcadciiokjpikmkkmapphbmdjok":    true,
		"https://kidstoreperu-frontend-react-dev.up.railway.app": true,
	}

	router.Use(cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			fmt.Println("CORS Origin Check:", origin)
			return allowedOrigins[origin]
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Accept", "Authorization"},
		ExposeHeaders:    []string{"X-Total-Count"},
		AllowWildcard:    true,
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	router.Use(genericMiddleware)

	gin.SetMode(gin.ReleaseMode)

	authorized := router.Group("/", AuthMiddleware())
	authorized.Use(genericMiddleware)

	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome Gin Server")
	})

	authorized.GET("/protected", func(ctx *gin.Context) {
		result := protectedEndpointHandler(ctx)
		if result != 200 {
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"message": "Welcome to the protected area"})
	})

	//login endpoint
	router.POST("/loginform", HandlerLoginForm(db, cfg.AdminUser))

	//user endpoints
	authorized.POST("/addnewuser", HandlerAddNewUser(db))
	authorized.POST("/removeusers", HandlerRemoveUsers(db))
	authorized.POST("/updateuser", HandlerUpdateUser(db))
	authorized.GET("/getalluser", HandlerGetAllUsers(db))

	//fortnite account endpoints
	authorized.POST("/disconnectfortniteaccount", HandlerDisconnectFAccount(db))
	authorized.GET("/fortniteaccountsofuser", HandlerGetGameAccountsByOwner(db))
	authorized.GET("/allfortniteaccounts", HandlerGetAllGameAccounts(db))
	//authorized.GET("/faccountstate", HandlerGetFAccountState(db))
	authorized.POST("/connectfaccount", HandlerAuthorizationCodeLogin(db, &refreshTokenList))
	authorized.POST("/sendGift", HandlerSendGift(db, &refreshTokenList))
	authorized.POST("/searchfortnitefriend", HandlerSearchOnlineFortniteAccount(db, &refreshTokenList))

	//fetch transactions
	authorized.GET("/transactions", HandlerGetTransactions(db))
	//common
	NestTokensInRefreshList(db, &refreshTokenList)

	//temp
	authorized.POST("/forcerefresh", HandlerRefreshToken(db, &refreshTokenList))

	//go StartFriendRequestHandler(db, cfg.AcceptFriendsInMinutes, &refreshTokenList) // Check every 5 minutes
	go StartTokenRefresher(db, &refreshTokenList) // Check every 10 minutes

	router.Run(":8080")
}

func HandlerGetTransactions(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := protectedEndpointHandler(c)
		if result != 200 {
			return
		}
		rows, err := db.Query(`SELECT id, game_account_id, sender_name, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at FROM transactions`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch transactions", "details": err.Error()})
			return
		}
		defer rows.Close()

		var transactions []Transaction
		for rows.Next() {
			var tx Transaction
			if err := rows.Scan(&tx.ID, &tx.GameAccountID, &tx.SenderName, &tx.ReceiverID, &tx.ReceiverName, &tx.ObjectStoreID, &tx.ObjectStoreName, &tx.RegularPrice, &tx.FinalPrice, &tx.GiftImage, &tx.CreatedAt); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not scan transaction", "details": err.Error()})
				return
			}
			transactions = append(transactions, tx)
		}
		c.JSON(http.StatusOK, transactions)
	}
}

func HandlerGetAllGameAccounts(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := adminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		accounts, err := GetAllGameAccounts(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch game accounts", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, accounts)
	}
}

func GetAllGameAccounts(db *sql.DB) ([]GameAccount, error) {
	var accounts []GameAccount
	rows, err := db.Query(`SELECT id, display_name, remaining_gifts, pavos, access_token, access_token_exp, access_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date FROM game_accounts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var account GameAccount
		if err := rows.Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.PaVos, &account.AccessToken, &account.AccessTokenExp, &account.AccessTokenExpDate, &account.RefreshToken, &account.RefreshTokenExp, &account.RefreshTokenExpDate); err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func NestTokensInRefreshList(db *sql.DB, refreshList *RefreshList) {
	// Get all game accounts from the database
	rows, err := db.Query(`SELECT id, access_token, access_token_exp_date, refresh_token FROM game_accounts`)
	if err != nil {
		fmt.Printf("Error fetching game accounts: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var account accountTokens
		if err := rows.Scan(&account.ID, &account.AccessToken, &account.AccessTokenExp, &account.RefreshToken); err != nil {
			fmt.Printf("Error scanning game account: %v", err)
			continue
		}
		//convert account.ID to string
		accountId := account.ID.String()

		//print accountId and account.ID
		fmt.Printf("Account ID: %s, Account ID (UUID): %s\n", accountId, account.ID.String())
		(*refreshList)[account.ID] = accountTokens{
			ID:             account.ID,
			AccessToken:    account.AccessToken,
			RefreshToken:   account.RefreshToken,
			AccessTokenExp: account.AccessTokenExp,
		}

	}
}

func genericMiddleware(c *gin.Context) {
	// Middleware logic here
	//Options for preflight requests
	if c.Request.Method == "OPTIONS" {
		c.JSON(http.StatusOK, nil)
		c.Abort()
		return
	}
	c.Next()
}

type FriendRequest struct {
	AccountID string `json:"accountId"`
	Groups    []any  `json:"groups"` // adjust type if needed
	Mutual    int    `json:"mutual"`
	Alias     string `json:"alias"`
	Note      string `json:"note"`
	Favorite  bool   `json:"favorite"`
	Created   string `json:"created"`
}

func StartFriendRequestHandler(db *sql.DB, intervalMinutes int, refreshList *RefreshList) {
	//we are using the refresh list here as it should contain ALL the accounts registered in the db
	//this is a bit of a hack, but it works

	client := &http.Client{Timeout: 10 * time.Second}

	for {
		time.Sleep(time.Duration(intervalMinutes) * time.Minute)

		for id, tokens := range *refreshList {
			//sleep for 1+random second to avoid rate limiting
			fmt.Printf("checking incoming friends of  %s", id)

			time.Sleep(time.Duration(rand.Float32()+1) * time.Second)
			friendRequests, err := getIncomingRequests(client, tokens, db, refreshList)
			//print friend requests
			fmt.Printf("Friend requests for account %s: %v\n", id, friendRequests)

			//remove - from the friend requests
			for i, friend := range friendRequests {
				friend.AccountID = strings.ReplaceAll(friend.AccountID, "-", "")
				friendRequests[i] = friend
			}
			//print friend requests again
			fmt.Printf("Friend requests for account %s after removing -: %v\n", id, friendRequests)

			if err != nil {
				fmt.Printf("Failed to get friend requests for account %s: %v\n", id, err)
				continue
			}

			if len(friendRequests) > 0 {
				fmt.Println()
				err := acceptFriendRequests(client, db, tokens, friendRequests, refreshList)
				if err != nil {
					fmt.Printf("Failed to accept friend requests for account %s: %v\n", id, err)
				} else {
					fmt.Printf("Accepted %d friend requests for account %s\n", len(friendRequests), id)
				}
			}
		}
	}
}

func getIncomingRequests(client *http.Client, account accountTokens, db *sql.DB, refreshList *RefreshList) ([]FriendRequest, error) {
	url := fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/incoming", account.ID.String())
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "bearer "+account.AccessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get incoming friend requests, status: %d", resp.StatusCode)
	}

	//if access token expired, refresh it
	if resp.StatusCode == 401 {
		fmt.Printf("Refreshing token of: %s\n", account.ID)
		newTokens, err := refreshAccessToken(client, account.RefreshToken, refreshList, db)
		if err != nil {
			fmt.Printf("Failed to refresh token: %v", err)
		}
		req.Header.Set("Authorization", "bearer "+newTokens.AccessToken)
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get incoming friend requests, status: %d", resp.StatusCode)
	}

	var friendRequests []FriendRequest
	err = json.NewDecoder(resp.Body).Decode(&friendRequests)
	if err != nil {
		return nil, err
	}

	return friendRequests, nil

}

func acceptFriendRequests(client *http.Client, db *sql.DB, account accountTokens, friends []FriendRequest, refreshList *RefreshList) error {
	for _, friend := range friends {
		fmt.Printf("Accepting friend request from %s\n", friend.AccountID)
		fmt.Printf("to account id %s\n", account.ID.String())

		url := fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/friends/%s", account.ID.String(), friend.AccountID)
		req, err := http.NewRequest("POST", url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "bearer "+account.AccessToken)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 204 {
			fmt.Printf("Accepted friend request from %s\n", friend.AccountID)
			return nil
		}

		if resp.StatusCode == 401 {
			//refresh token and try again
			fmt.Printf("Refreshing token of: %s\n", account.ID.String())
			newTokens, err := refreshAccessToken(client, account.RefreshToken, refreshList, db)
			if err != nil {
				fmt.Printf("Failed to refresh token: %v", err)
			}
			req.Header.Set("Authorization", "bearer "+newTokens.AccessToken)
		}
		resp, err = client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 204 {
			fmt.Printf("Accepted friend request from %s\n", friend.AccountID)
			return nil
		}

		if resp.StatusCode != 204 {
			return fmt.Errorf("failed to accept friend %s, status: %d", friend.AccountID, resp.StatusCode)
		}
	}
	return nil
}

type accountTokens struct {
	ID             uuid.UUID
	AccessTokenExp time.Time
	RefreshToken   string
	AccessToken    string
}

type RefreshList map[uuid.UUID]accountTokens

// loop, check if token is less than 15 minutes away from expiring, if so, refresh it
func StartTokenRefresher(db *sql.DB, refreshList *RefreshList) {
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		time.Sleep(time.Duration(10) * time.Minute)

		for id, tokenInfo := range *refreshList {
			if time.Until(tokenInfo.AccessTokenExp) < 15*time.Minute {
				fmt.Printf("Refreshing token for account %s\n", id)
				_, err := refreshAccessToken(client, tokenInfo.RefreshToken, refreshList, db)
				if err != nil {
					fmt.Printf("Failed to refresh token: %v", err)
					continue
				}

			}
		}
	}
}

func refreshAccessToken(client *http.Client, refreshToken string, refreshList *RefreshList, db *sql.DB) (LoginResultResponse, error) {
	form := url.Values{}
	authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte("ec684b8c687f479fadea3cb2ad83f5c6:e1f31c211f28413186262d37a13fc84d"))

	form.Add("grant_type", "refresh_token")
	form.Add("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return LoginResultResponse{}, err
	}

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return LoginResultResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		//delete account from refreshList and DB
		fmt.Printf("Failed to refresh token, status code: %d\n", resp.StatusCode)
		//remove from refreshList
		for accountId := range *refreshList {
			if (*refreshList)[accountId].RefreshToken == refreshToken {
				delete(*refreshList, accountId)
				fmt.Printf("Removed account %s from refresh list due to token refresh failure\n", accountId)
				//remove from DB
				err := DeleteGameAccountByID(db, accountId)
				if err != nil {
					fmt.Printf("Failed to delete game account from DB: %v", err)
					return LoginResultResponse{}, fmt.Errorf("removed account %s from DB due to token refresh failure\n", accountId)
				}
				fmt.Printf("Removed account %s from DB due to token refresh failure\n", accountId)
				return LoginResultResponse{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			}
		}
	}

	var tokenResult LoginResultResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResult)
	if err != nil {
		return LoginResultResponse{}, err
	}

	AccountId, err := uuid.Parse(tokenResult.AccountId)
	if err != nil {
		fmt.Printf("Failed to parse game ID: %v", err)
		return LoginResultResponse{}, err
	}

	//UPDATE refreshList
	(*refreshList)[AccountId] = accountTokens{
		ID:             AccountId,
		AccessTokenExp: time.Now().Add(time.Duration(tokenResult.AccessTokenExpiration) * time.Second),
		RefreshToken:   tokenResult.RefreshToken,
		AccessToken:    tokenResult.AccessToken,
	}

	//UPDATE DB
	gameId, err := uuid.Parse(tokenResult.AccountId)
	if err != nil {
		fmt.Printf("Failed to parse game ID: %v", err)
		return LoginResultResponse{}, err
	}

	err = UpdateGameAccount(db, GameAccount{
		ID:                  gameId,
		DisplayName:         tokenResult.DisplayName,
		RemainingGifts:      0,
		PaVos:               0,
		AccessToken:         tokenResult.AccessToken,
		AccessTokenExp:      tokenResult.AccessTokenExpiration,
		AccessTokenExpDate:  time.Now().Add(time.Duration(tokenResult.AccessTokenExpiration) * time.Second),
		RefreshToken:        tokenResult.RefreshToken,
		RefreshTokenExp:     tokenResult.RefreshTokenExpiration,
		RefreshTokenExpDate: time.Now().Add(time.Duration(tokenResult.RefreshTokenExpiration) * time.Second),
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	})
	if err != nil {
		fmt.Printf("Failed to update token in DB: %v", err)
		return LoginResultResponse{}, err
	}

	return tokenResult, nil
}

// return current user fortnite accounts
func GetGameAccountsByOwner(db *sql.DB, ownerUserID uuid.UUID) ([]GameAccount, error) {
	query := `SELECT id, display_name, remaining_gifts, access_token, refresh_token, created_at, updated_at FROM game_accounts WHERE owner_user_id = $1`
	rows, err := db.Query(query, ownerUserID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var accounts []GameAccount
	for rows.Next() {
		var account GameAccount

		err := rows.Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.AccessToken, &account.RefreshToken, &account.CreatedAt, &account.UpdatedAt)
		if err != nil {
			return nil, err
		}

		accounts = append(accounts, account)
	}
	return accounts, nil
}

// endpoint to send all game accounts of the user
func HandlerGetGameAccountsByOwner(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := protectedEndpointHandler(c)
		if result != 200 {
			return
		}

		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user UUID format", "details": err.Error()})
			return
		}

		gameAccounts, err := GetGameAccountsByOwner(db, userUUID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch game accounts", "details": err.Error()})
			return
		}

		//print game accounts

		// Map to simplified response
		type SimplifiedAccount struct {
			ID             string `json:"id"`
			DisplayName    string `json:"displayName"`
			Pavos          int    `json:"pavos"`
			RemainingGifts int    `json:"remainingGifts"`
		}

		var resultAccounts []SimplifiedAccount = []SimplifiedAccount{}
		for _, account := range gameAccounts {
			resultAccounts = append(resultAccounts, SimplifiedAccount{
				ID:             account.ID.String(),
				DisplayName:    account.DisplayName,
				Pavos:          0, // You can replace this with actual V-Bucks if you track them
				RemainingGifts: account.RemainingGifts,
			})
		}

		c.JSON(http.StatusOK, resultAccounts)
	}
}

// endpoint handler to send gift
func HandlerSendGift(db *sql.DB, refreshList *RefreshList) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := protectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req struct {
			AccountID    string `json:"account_id" binding:"required"`
			SenderName   string `json:"sender_username" binding:"required"`
			ReceiverID   string `json:"receiver_id" binding:"required"`
			ReceiverName string `json:"receiver_username" binding:"required"`
			GiftId       string `json:"gift_id" binding:"required"`
			GiftPrice    int    `json:"gift_price" binding:"required"`
			GiftName     string `json:"gift_name" binding:"required"`
			Message      string `json:"message" binding:"required"`
			GiftImage    string `json:"gift_image" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		AccountId, err := uuid.Parse(req.AccountID)
		if err != nil {
			fmt.Printf("Failed to parse game ID: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid account ID format", "details": err.Error()})
			return
		}

		//fetch access token from refresh list
		tokens, ok := (*refreshList)[AccountId]
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Account not found in refresh list"})
			return
		}

		//print tokens
		fmt.Printf("Tokens for account %s: %+v\n", AccountId, tokens)

		//remove - from the receiver ID and AccountID
		req.AccountID = strings.ReplaceAll(req.AccountID, "-", "")
		req.ReceiverID = strings.ReplaceAll(req.ReceiverID, "-", "")

		err = sendGiftRequest(req.AccountID, req.ReceiverID, req.GiftId, req.GiftPrice, tokens.AccessToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not send gift", "details": err.Error()})
			return
		}

		err = AddTransaction(db, Transaction{
			ID:              uuid.New(),
			GameAccountID:   AccountId,
			SenderName:      &req.SenderName, // Assuming this is the sender's account ID
			ReceiverID:      &req.ReceiverID,
			ReceiverName:    &req.ReceiverName,
			ObjectStoreID:   req.GiftId,
			ObjectStoreName: req.GiftName,
			RegularPrice:    float64(req.GiftPrice),
			FinalPrice:      float64(req.GiftPrice),
			GiftImage:       req.GiftImage,
			CreatedAt:       time.Now(),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not add transaction", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Gift sent successfully"})

	}
}

func sendGiftRequest(accountID string, userID string, giftItem string, giftPrice int, accessToken string) error {
	client := &http.Client{Timeout: 10 * time.Second}

	payload := map[string]interface{}{
		"offerId":            giftItem,
		"currency":           "MtxCurrency",
		"currencySubType":    "",
		"expectedTotalPrice": giftPrice,
		"gameContext":        "Frontend.CatabaScreen",
		"receiverAccountIds": []string{userID},
		"giftWrapTemplateId": "",
		"personalMessage":    "",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://fngw-mcp-gc-livefn.ol.epicgames.com/fortnite/api/game/v2/profile/%s/client/GiftCatalogEntry?profileId=common_core", accountID),
		bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	//print response
	fmt.Printf("Response status: %s\n", resp.Status)
	fmt.Printf("Response: %s\n", resp.Proto)

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to send gift, status: %d", resp.StatusCode)
	}

	return nil
}

// func send_gift_request(account_id, access_token, offer_id, final_price, user_id):
//   url = f"https://fngw-mcp-gc-livefn.ol.epicgames.com/fortnite/api/game/v2/profile/{account_id}/client/GiftCatalogEntry?profileId=common_core"
//   payload = {
//       "offerId": offer_id,
//       "currency": "MtxCurrency",
//       "currencySubType": "",
//       "expectedTotalPrice": final_price,
//       "gameContext": "Frontend.CatabaScreen",
//       "receiverAccountIds": [user_id],
//       "giftWrapTemplateId": "",
//       "personalMessage": ""
//   }
//   headers = {
//       "Content-Type": "application/json",
//       "Authorization": f"Bearer {access_token}"
//   }

//   response = requests.post(url, json=payload, headers=headers)
//   with open('config.json', 'r') as file:
//     account_data = json.load(file)
//   for account_info in account_data:
//     device_id = account_info['deviceId']
//     secret = account_info['secret']
//   if response.status_code == 200:
//     print(f"[{account_info['accountId']}] Sent cosmetic gift to {user_id}")

// Handle Authorization_Code login  (input authorization code) output:
//raw example

// POST /account/api/oauth/token HTTP/1.1
// Accept: */*
// Accept-Encoding: deflate, gzip
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0
// Authorization: basic ZWM2ODRiOGM2ODdmNDc5ZmFkZWEzY2IyYWQ4M2Y1YzY6ZTFmMzFjMjExZjI4NDEzMTg2MjYyZDM3YTEzZmM4NGQ=
// Host: account-public-service-prod.ol.epicgames.com
// Content-Type: application/x-www-form-urlencoded
// Content-Length: 67

// grant_type=authorization_code&code=14e04b40b04f46d1a0436802995d555c

//response type LoginResultResponse

func HandlerAuthorizationCodeLogin(db *sql.DB, refreshList *RefreshList) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := protectedEndpointHandler(c)
		if result != 200 {
			return
		}

		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		//print userID
		fmt.Printf("User ID: %s\n", userID)

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		userUUID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user UUID format", "details": err.Error()})
			return
		}

		var req struct {
			Code string `json:"code" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		client := &http.Client{Timeout: 10 * time.Second}
		authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte("ec684b8c687f479fadea3cb2ad83f5c6:e1f31c211f28413186262d37a13fc84d"))

		reqToken, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(
			fmt.Sprintf("grant_type=authorization_code&code=%s", req.Code),
		))
		reqToken.Header.Set("Authorization", authHeader)
		reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		respToken, err := client.Do(reqToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not get client token", "details": err.Error()})
			return
		}
		defer respToken.Body.Close()

		var tokenResult LoginResultResponse
		if err := json.NewDecoder(respToken.Body).Decode(&tokenResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid client token response", "details": err.Error()})
			return
		}
		gameId, err := uuid.Parse(tokenResult.AccountId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid game account ID", "details": err.Error()})
			return
		}
		if gameId == uuid.Nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid game account ID"})
			return
		}

		//print gameId and user UUID
		fmt.Printf("Game ID: %s, User UUID: %s\n", gameId.String(), userUUID.String())

		err = AddGameAccount(db, GameAccount{
			ID:                  gameId,
			DisplayName:         tokenResult.DisplayName,
			RemainingGifts:      0,
			PaVos:               0,
			AccessToken:         tokenResult.AccessToken,
			AccessTokenExp:      tokenResult.AccessTokenExpiration,
			AccessTokenExpDate:  time.Now().Add(time.Duration(tokenResult.AccessTokenExpiration) * time.Second),
			RefreshToken:        tokenResult.RefreshToken,
			RefreshTokenExp:     tokenResult.RefreshTokenExpiration,
			RefreshTokenExpDate: time.Now().Add(time.Duration(tokenResult.RefreshTokenExpiration) * time.Second),
			OwnerUserID:         userUUID,
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save game account", "details": err.Error()})
			return
		}

		//convert to uuid
		AccountId, err := uuid.Parse(tokenResult.AccountId)
		if err != nil {
			fmt.Printf("Failed to parse game ID: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid account ID format", "details": err.Error()})
			return
		}

		// Add the new token to the refresh list
		(*refreshList)[AccountId] = accountTokens{
			ID:             gameId,
			AccessTokenExp: time.Now().Add(time.Duration(tokenResult.AccessTokenExpiration) * time.Second),
			RefreshToken:   tokenResult.RefreshToken,
			AccessToken:    tokenResult.AccessToken,
		}

		//print prettified refreshList
		fmt.Printf("Refresh List: %v\n", *refreshList)

		c.JSON(http.StatusOK, gin.H{"message": "Fortnite account connected successfully", "id": tokenResult.AccountId, "username": tokenResult.DisplayName})
	}
}

//handle search for fortnite account by username HandlerSearchOnlineFortniteAccount
// GET /account/api/public/account/displayName/kidStore0002 HTTP/1.1
// Accept: */*
// Accept-Encoding: deflate, gzip
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0
// Authorization: Bearer 30dc3800b33a47b199a32e37789efbe8
// Host: account-public-service-prod.ol.epicgames.com

func HandlerSearchOnlineFortniteAccount(db *sql.DB, refreshList *RefreshList) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := protectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req struct {
			DisplayName string `json:"display_name" binding:"required"`
			AccountId   string `json:"account_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		client := &http.Client{Timeout: 10 * time.Second}
		//get user account from refresh list
		//print refreshList
		fmt.Printf("Refresh List: %v\n", *refreshList)
		//print userID
		fmt.Printf("User ID: %s\n", req.AccountId)

		AccountId, err := uuid.Parse(req.AccountId)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid account ID format", "details": err.Error()})
			return
		}
		userAccount, ok := (*refreshList)[AccountId]
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User account not found"})
			return
		}

		reqToken, _ := http.NewRequest("GET", fmt.Sprintf("https://account-public-service-prod.ol.epicgames.com/account/api/public/account/displayName/%s", req.DisplayName), nil)
		reqToken.Header.Set("Authorization", "Bearer "+userAccount.AccessToken)

		respToken, err := client.Do(reqToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se encontro al usuario", "details": err.Error()})
			return
		}
		defer respToken.Body.Close()

		//print response
		fmt.Printf("Response: %s\n", respToken.Status)

		type publicAccountResult struct {
			AccountId   string `json:"id"`
			DisplayName string `json:"displayName"`
		}

		var tokenResult publicAccountResult
		if err := json.NewDecoder(respToken.Body).Decode(&tokenResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "No se encontro al usuario.", "details": err.Error()})
			return
		}

		//userAccount.IDtoSTR WITHOUT -
		userAccountIDtoSTR := strings.ReplaceAll(userAccount.ID.String(), "-", "")

		//then check in friends list with id (currentuser id, then friend id)
		// GET /friends/api/v1/aa4a645d589d41478300d8af9741f294/friends/11406cf858f042bc902bb83a53063d3e?displayAlias=true HTTP/1.1
		// Accept: */*
		// Accept-Encoding: deflate, gzip
		// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0
		// Authorization: Bearer 65cb2fe6cf334f129faf36369949fb61
		// Host: friends-public-service-prod.ol.epicgames.com
		//print
		fmt.Printf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/friends/%s", userAccountIDtoSTR, tokenResult.AccountId)
		fmt.Printf("\nUser Account: %s\n", userAccount.AccessToken)

		reqFriends, _ := http.NewRequest("GET", fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/friends/%s", userAccountIDtoSTR, tokenResult.AccountId), nil)
		reqFriends.Header.Set("Authorization", "Bearer "+userAccount.AccessToken)

		//print request
		fmt.Printf("Request: %s\n", reqFriends.URL)
		fmt.Printf("Request: %s\n", reqFriends.Header)
		//print request body
		fmt.Printf("Request: %s\n", reqFriends.Body)

		respFriends, err := client.Do(reqFriends)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "El usuario no es amigo", "details": err.Error()})
			return
		}
		defer respFriends.Body.Close()
		if respFriends.StatusCode == 401 {
			//refresh the token
			fmt.Printf("Refreshing token of: %s\n", userAccount.ID.String())
			newTokens, err := refreshAccessToken(client, userAccount.RefreshToken, refreshList, db)
			if err != nil {
				fmt.Printf("Failed to refresh token: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not refresh access token", "details": err.Error()})
				return
			}
			reqFriends.Header.Set("Authorization", "Bearer "+newTokens.AccessToken)
			respFriends, err = client.Do(reqFriends)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not get client token", "details": err.Error()})
				return
			}
		}
		if respFriends.StatusCode != 200 {
			var errorResponse struct {
				ErrorCode    string   `json:"errorCode"`
				ErrorMessage string   `json:"errorMessage"`
				MessageVars  []string `json:"messageVars"`
			}
			//print response
			fmt.Printf("Response: %s\n", respFriends.Status)
			fmt.Printf("Response: %s\n", respFriends.Header)

			if err := json.NewDecoder(respFriends.Body).Decode(&errorResponse); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "El usuario no es amigo.", "details": err.Error()})
				return
			}
			// Check if the error code is "errors.com.epicgames.friends.friendship_not_found"
			if respFriends.StatusCode == 404 && errorResponse.ErrorCode == "errors.com.epicgames.friends.friendship_not_found" {
				c.JSON(http.StatusNotFound, gin.H{"error": "El usuario no esta en la lista de amigos", "details": errorResponse.ErrorMessage})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not get client token", "details": errorResponse.ErrorMessage})
			return
		}
		type FriendResult struct {
			AccountId string `json:"accountId"`
			Alias     string `json:"alias"`
			Created   string `json:"created"`
		}
		var friendResult FriendResult
		if err := json.NewDecoder(respFriends.Body).Decode(&friendResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Usuario no encontrado", "details": err.Error()})
			return
		}
		//check if the account is in the friends list for more than 48 hours
		//if friendResult.Created > 48 hours
		friendCreated, err := time.Parse(time.RFC3339, friendResult.Created)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid friend created date", "details": err.Error()})
			return
		}
		if time.Since(friendCreated) > 48*time.Hour {

			//parse created to dd/mm/yyyy, hh:mm in gtm -5
			friendCreatedStr := friendCreated.Format("02/01/2006 15:04")
			friendCreatedStr = friendCreatedStr + " GMT-5"
			c.JSON(http.StatusOK, gin.H{"giftable": true, "friend": true, "user": true, "accountId": tokenResult.AccountId, "displayName": tokenResult.DisplayName, "created": friendCreatedStr})
			return
		}

	}

}

// trigge refresh of tokens based on account id
func HandlerRefreshToken(db *sql.DB, refreshList *RefreshList) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := protectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req struct {
			AccountId string `json:"account_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		//print request
		fmt.Printf("Refresh Token Request: %v\n", req)
		//print refreshList
		fmt.Printf("Refresh List in ref: %v\n", *refreshList)

		AccountId, err := uuid.Parse(req.AccountId)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid account ID format", "details": err.Error()})
			return
		}

		tokens, ok := (*refreshList)[AccountId]
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Account not found in refresh list"})
			return
		}

		newTokens, err := refreshAccessToken(&http.Client{Timeout: 10 * time.Second}, tokens.RefreshToken, refreshList, db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not refresh access token", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Access token refreshed successfully", "newAccessToken": newTokens.AccessToken})
	}
}

// //handle verify if access token is valid
