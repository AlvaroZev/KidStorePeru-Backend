package main

import (
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

type deviceResultResponse struct {
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
	ID               uuid.UUID
	GameAccountID    uuid.UUID
	ReceiverID       *string
	ReceiverUsername *string
	ObjectStoreID    string
	ObjectStoreName  string
	RegularPrice     float64
	FinalPrice       float64
	CreatedAt        time.Time
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
	_, err := db.Exec(`INSERT INTO game_accounts (id, display_name, remaining_gifts, pavos, access_token, acces_token_exp, acces_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date, owner_user_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), now())`, account.ID, account.DisplayName, account.RemainingGifts, account.PaVos, account.AccessToken, account.AccessTokenExp, account.AccessTokenExpDate, account.RefreshToken, account.RefreshTokenExp, account.RefreshTokenExpDate, account.OwnerUserID)
	if err != nil {
		fmt.Printf("Error adding game account: %v", err)
	}
	return err
}

func DeleteGameAccountByUsername(db *sql.DB, username string, ownerID uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM game_accounts WHERE username = $1 AND owner_user_id = $2`, username, ownerID)
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

func DeleteGameAccountByID(db *sql.DB, id uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM game_accounts WHERE id = $1`, id)
	return err
}

func GetGameAccountByOwner(db *sql.DB, ownerID uuid.UUID) (GameAccount, error) {
	var account GameAccount
	err := db.QueryRow(`SELECT id, display_name, remaining_gifts, pavos, access_token, acces_token_exp, acces_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date FROM game_accounts WHERE owner_user_id = $1`, ownerID).Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.PaVos, &account.AccessToken, &account.AccessTokenExp, &account.AccessTokenExpDate, &account.RefreshToken, &account.RefreshTokenExp, &account.RefreshTokenExpDate)
	if err != nil {
		fmt.Printf("Error getting game account: %v", err)
		return GameAccount{}, err
	}
	return account, nil

}

func GetGameAccount(db *sql.DB, id uuid.UUID) (GameAccount, error) {
	var account GameAccount
	err := db.QueryRow(`SELECT id, display_name, remaining_gifts, pavos, access_token, acces_token_exp, acces_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date FROM game_accounts WHERE id = $1`, id).Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.PaVos, &account.AccessToken, &account.AccessTokenExp, &account.AccessTokenExpDate, &account.RefreshToken, &account.RefreshTokenExp, &account.RefreshTokenExpDate)
	if err != nil {
		fmt.Printf("Error getting game account: %v", err)
		return GameAccount{}, err
	}
	return account, nil
}

func UpdateGameAccount(db *sql.DB, account GameAccount) error {
	_, err := db.Exec(`UPDATE game_accounts SET display_name = $1, remaining_gifts = $2, pavos = $3, access_token = $4, acces_token_exp = $5, acces_token_exp_date = $6, refresh_token = $7, refresh_token_exp = $8, refresh_token_exp_date = $9 WHERE id = $10`, account.DisplayName, account.RemainingGifts, account.PaVos, account.AccessToken, account.AccessTokenExp, account.AccessTokenExpDate, account.RefreshToken, account.RefreshTokenExp, account.RefreshTokenExpDate, account.ID)
	return err
}

func DeleteGameAccount(db *sql.DB, id uuid.UUID) error {
	_, err := db.Exec(`DELETE FROM game_accounts WHERE id = $1`, id)
	return err
}

// ========== TRANSACTION METHODS ==========
func AddTransaction(db *sql.DB, tx Transaction) error {
	_, err := db.Exec(`INSERT INTO transactions (id, game_account_id, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())`, tx.ID, tx.GameAccountID, tx.ReceiverID, tx.ReceiverUsername, tx.ObjectStoreID, tx.ObjectStoreName, tx.RegularPrice, tx.FinalPrice)
	return err
}

func GetTransaction(db *sql.DB, id uuid.UUID) (Transaction, error) {
	var tx Transaction
	err := db.QueryRow(`SELECT id, game_account_id, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, created_at FROM transactions WHERE id = $1`, id).Scan(&tx.ID, &tx.GameAccountID, &tx.ReceiverID, &tx.ReceiverUsername, &tx.ObjectStoreID, &tx.ObjectStoreName, &tx.RegularPrice, &tx.FinalPrice, &tx.CreatedAt)
	return tx, err
}

func UpdateTransaction(db *sql.DB, tx Transaction) error {
	_, err := db.Exec(`UPDATE transactions SET receiver_id = $1, receiver_username = $2, object_store_id = $3, object_store_name = $4, regular_price = $5, final_price = $6 WHERE id = $7`, tx.ReceiverID, tx.ReceiverUsername, tx.ObjectStoreID, tx.ObjectStoreName, tx.RegularPrice, tx.FinalPrice, tx.ID)
	return err
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

func GetEpicFriendsState(accessToken string, accountId string) ([]string, []string, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Get incoming friend requests
	req1, _ := http.NewRequest("GET", fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/incoming", accountId), nil)
	req1.Header.Set("Authorization", "bearer "+accessToken)
	resp1, err := client.Do(req1)
	if err != nil {
		return nil, nil, err
	}
	defer resp1.Body.Close()

	var incoming []accountIdStr
	if err := json.NewDecoder(resp1.Body).Decode(&incoming); err != nil {
		return nil, nil, err
	}

	// Get existing friends
	req2, _ := http.NewRequest("GET", fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/friends", accountId), nil)
	req2.Header.Set("Authorization", "bearer "+accessToken)
	resp2, err := client.Do(req2)
	if err != nil {
		return nil, nil, err
	}
	defer resp2.Body.Close()

	var friends []accountIdStr
	if err := json.NewDecoder(resp2.Body).Decode(&friends); err != nil {
		return nil, nil, err
	}

	// Collect IDs
	var incomingIDs []string
	for _, f := range incoming {
		incomingIDs = append(incomingIDs, f.AccountId)
	}
	var friendsIDs []string
	for _, f := range friends {
		friendsIDs = append(friendsIDs, f.AccountId)
	}

	return incomingIDs, friendsIDs, nil
}

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
			Username string `json:"username" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		err := DeleteGameAccountByUsername(db, req.Username, userID.(uuid.UUID))
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

	var refreshTokenList RefreshList

	router := gin.Default()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	allowedOrigins := map[string]bool{
		"*":                                true,
		"http://localhost:5173":            true,
		"https://your-production-site.com": true,
		"chrome-extension://gmmkjpcadciiokjpikmkkmapphbmdjok": true,
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

	authorized.POST("/addnewuser", HandlerAddNewUser(db))
	authorized.POST("/removeusers", HandlerRemoveUsers(db))
	authorized.POST("/updateuser", HandlerUpdateUser(db))
	authorized.GET("/getalluser", HandlerGetAllUsers(db))
	authorized.POST("/disconnectfortniteaccount", HandlerDisconnectFAccount(db))
	authorized.GET("/fortniteaccountsofuser", HandlerGetGameAccountsByOwner(db))
	//authorized.GET("/faccountstate", HandlerGetFAccountState(db))
	//Falta: go routine para revisar periodicamente por solicitudes de amistad

	router.POST("/loginform", HandlerLoginForm(db, cfg.AdminUser))

	authorized.POST("/connectfaccount", HandlerAuthorizationCodeLogin(db, &refreshTokenList))

	//go UpdateTokensPeriodically(db, &list_ofPendingRequests)
	go StartFriendRequestHandler(db, cfg.AcceptFriendsInMinutes, &refreshTokenList) // Check every 5 minutes
	go StartTokenRefresher(db, &refreshTokenList)                                   // Check every 10 minutes
	router.Run(":8080")
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
	url := fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/incoming", account.ID)
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
		url := fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/friends/%s", account.ID, friend.AccountID)
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
			fmt.Printf("Refreshing token of: %s\n", account.ID)
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
	ID             string
	AccessTokenExp time.Time
	RefreshToken   string
	AccessToken    string
}

// struct map (id) => {access_token_exp_time, refresh_token}
type RefreshList map[string]accountTokens

// loop, check if token is less than 15 minutes away from expiring, if so, refresh it
func StartTokenRefresher(db *sql.DB, refreshList *RefreshList) {
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		time.Sleep(time.Duration(10) * time.Minute)

		for id, tokenInfo := range *refreshList {
			if time.Until(tokenInfo.AccessTokenExp) < 15*time.Minute {
				fmt.Printf("Refreshing token for account %s\n", id)
				//TODO CHECK why here not * in refreshList, because it is a pointer and not a struct???
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
		return LoginResultResponse{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var tokenResult LoginResultResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResult)
	if err != nil {
		return LoginResultResponse{}, err
	}

	//UPDATE refreshList
	(*refreshList)[tokenResult.AccountId] = accountTokens{
		ID:             tokenResult.AccountId,
		AccessTokenExp: time.Now().Add(time.Duration(tokenResult.AccessTokenExpiration) * time.Second),
		RefreshToken:   tokenResult.RefreshToken,
		AccessToken:    tokenResult.AccessToken,
	}

	//UPDATE DB
	var gameId uuid.UUID = uuid.MustParse(tokenResult.AccountId)

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

		c.JSON(http.StatusOK, gameAccounts)
	}
}

// endpoint handler to send gift
// func HandlerSendGift(db *sql.DB) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		result := protectedEndpointHandler(c)
// 		if result != 200 {
// 			return
// 		}

// 		userID, exists := c.Get("userID")
// 		if !exists {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
// 			return
// 		}

// 		userIDStr, ok := userID.(string)
// 		if !ok {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
// 			return
// 		}

// 		userUUID, err := uuid.Parse(userIDStr)
// 		if err != nil {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user UUID format", "details": err.Error()})
// 			return
// 		}

// 		var req struct {
// 			AccountID string `json:"account_id" binding:"required"`
// 			UserID    string `json:"user_id" binding:"required"`
// 			GiftItem  string `json:"gift_item" binding:"required"`
// 			GiftPrice int    `json:"gift_price" binding:"required"`
// 			GiftWrap  string `json:"gift_wrap" binding:"required"`
// 			Message   string `json:"message" binding:"required"`
// 		}
// 		if err := c.ShouldBindJSON(&req); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}

// 		err = sendGiftRequest(req.AccountID, req.UserID, req.GiftItem, req.GiftPrice, req.GiftWrap, req.Message)
// 		if err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not send gift", "details": err.Error()})
// 			return
// 		}

// 		c.JSON(http.StatusOK, gin.H{"message": "Gift sent successfully"})
// 	}
// }

// def send_gift_request(account_id, access_token, offer_id, final_price, user_id):
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
		var gameId uuid.UUID = uuid.MustParse(tokenResult.AccountId)

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

		// Add the new token to the refresh list
		(*refreshList)[tokenResult.AccountId] = accountTokens{
			ID:             tokenResult.AccountId,
			AccessTokenExp: time.Now().Add(time.Duration(tokenResult.AccessTokenExpiration) * time.Second),
			RefreshToken:   tokenResult.RefreshToken,
			AccessToken:    tokenResult.AccessToken,
		}

		c.JSON(http.StatusOK, gin.H{"message": "Fortnite account connected successfully", "id": tokenResult.AccountId, "username": tokenResult.DisplayName})
	}
}

//handle search for fortnite account by username
// GET /account/api/public/account/displayName/kidStore0002 HTTP/1.1
// Accept: */*
// Accept-Encoding: deflate, gzip
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0
// Authorization: Bearer 30dc3800b33a47b199a32e37789efbe8
// Host: account-public-service-prod.ol.epicgames.com

// //handle verify if access token is valid
