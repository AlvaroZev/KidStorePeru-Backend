package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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
	Host      string `envconfig:"DB_HOST" default:"postgres.railway.internal"`
	Port      int    `envconfig:"DB_PORT" default:"5432"`
	User      string `envconfig:"DB_USER"`
	Password  string `envconfig:"DB_PASSWORD"`
	DBName    string `envconfig:"DB_NAME"`
	SecretKey string `envconfig:"SECRET_KEY"`
	AdminUser string `envconfig:"ADMIN_USER"`
	AdminPass string `envconfig:"ADMIN_PASS"`
}

type AccessTokenResult struct {
	AccessToken string `json:"access_token"`
}

type deviceResultResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUriComplete string `json:"verification_uri_complete"`
}

type loginResultResponse struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	AccountId      string `json:"account_id"`
	DisplayName    string `json:"displayName"`
	ExpiresIn      int    `json:"expires_in"`
	RefreshExpires int    `json:"refresh_expires"`
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
	ID             uuid.UUID
	Username       string
	RemainingGifts int
	AccessToken    string
	RefreshToken   string
	OwnerUserID    uuid.UUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
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
	_, err := db.Exec(`
		INSERT INTO game_accounts (
			id, username, remaining_gifts, access_token, refresh_token, owner_user_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, now(), now())
	`,
		account.ID,
		account.Username,
		account.RemainingGifts,
		account.AccessToken,
		account.RefreshToken,
		account.OwnerUserID,
	)
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

func GetGameAccountByOwner(db *sql.DB, ownerID uuid.UUID) (GameAccount, error) {
	var account GameAccount
	err := db.QueryRow(`SELECT id, username, remaining_gifts, access_token, owner_user_id, created_at, updated_at FROM game_accounts WHERE owner_user_id = $1`, ownerID).
		Scan(&account.ID, &account.Username, &account.RemainingGifts, &account.AccessToken, &account.OwnerUserID, &account.CreatedAt, &account.UpdatedAt)
	return account, err
}

func GetGameAccount(db *sql.DB, id uuid.UUID) (GameAccount, error) {
	var account GameAccount
	err := db.QueryRow(`SELECT id, username, remaining_gifts, access_token, owner_user_id, created_at, updated_at FROM game_accounts WHERE id = $1`, id).Scan(&account.ID, &account.Username, &account.RemainingGifts, &account.AccessToken, &account.OwnerUserID, &account.CreatedAt, &account.UpdatedAt)
	return account, err
}

func UpdateGameAccount(db *sql.DB, account GameAccount) error {
	_, err := db.Exec(`UPDATE game_accounts SET username = $1, remaining_gifts = $2, access_token = $3, updated_at = now() WHERE id = $4`, account.Username, account.RemainingGifts, account.AccessToken, account.ID)
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

func HandlerRemoveUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := adminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		var ids []uuid.UUID
		if err := c.ShouldBindJSON(&ids); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := DeleteUsersByIds(db, ids)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not remove users", "details": err.Error()})
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
func HandlerConnectFAccount(db *sql.DB, list_ofPendingRequests *[]AccountsToConnect) gin.HandlerFunc {
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

		client := &http.Client{Timeout: 10 * time.Second}
		authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte("98f7e42c2e3a4f86a74eb43fbb41ed39:0a2449a2-001a-451e-afec-3e812901c4d7"))

		// Step 1: Get client credentials token
		reqToken, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(
			"grant_type=client_credentials",
		))
		reqToken.Header.Set("Authorization", authHeader)
		reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		respToken, err := client.Do(reqToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not get client token", "details": err.Error()})
			return
		}
		defer respToken.Body.Close()

		var tokenResult AccessTokenResult
		if err := json.NewDecoder(respToken.Body).Decode(&tokenResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid client token response", "details": err.Error()})
			return
		}

		// Step 2: Request Device Auth URL
		reqDevice, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/deviceAuthorization", nil)
		reqDevice.Header.Set("Authorization", "bearer "+tokenResult.AccessToken)
		reqDevice.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		respDevice, err := client.Do(reqDevice)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not initiate device authorization", "details": err.Error()})
			return
		}
		defer respDevice.Body.Close()

		var deviceResult deviceResultResponse
		if err := json.NewDecoder(respDevice.Body).Decode(&deviceResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid device authorization response", "details": err.Error()})
			return
		}

		// Step 3: Send login URL back to user
		c.JSON(http.StatusOK, gin.H{
			"message":                   "Please complete Fortnite login",
			"verification_uri_complete": deviceResult.VerificationUriComplete,
			"user_code":                 deviceResult.UserCode,
		})
		pending_request := AccountsToConnect{
			User_id:     userUUID,
			Device_code: deviceResult.DeviceCode,
		}
		*list_ofPendingRequests = append(*list_ofPendingRequests, pending_request)

	}
}

func UpdateTokensPeriodically(db *sql.DB, list_ofPendingRequests *[]AccountsToConnect) {
	for {
		time.Sleep(7 * time.Second) // wait before polling again
		if len(*list_ofPendingRequests) == 0 {
			return
		}
		for _, pendingRequest := range *list_ofPendingRequests {

			fmt.Print("Polling for token...")
			reqPoll, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(
				"grant_type=device_code&device_code="+pendingRequest.Device_code,
			))
			authHeaderf := "basic " + base64.StdEncoding.EncodeToString([]byte("98f7e42c2e3a4f86a74eb43fbb41ed39:0a2449a2-001a-451e-afec-3e812901c4d7"))

			reqPoll.Header.Set("Authorization", authHeaderf)
			reqPoll.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			client := &http.Client{Timeout: 10 * time.Second}

			respPoll, err := client.Do(reqPoll)
			if err != nil {
				continue
			}
			defer respPoll.Body.Close()

			if respPoll.StatusCode == 400 {
				// not authorized yet
				continue
			}

			if respPoll.StatusCode != 200 {
				continue
			}

			var loginResult loginResultResponse
			if err := json.NewDecoder(respPoll.Body).Decode(&loginResult); err != nil {
				return
			}

			// Save account info to DB
			err = AddGameAccount(db, GameAccount{
				ID:             uuid.New(),
				Username:       loginResult.DisplayName,
				RemainingGifts: 0,
				AccessToken:    loginResult.AccessToken,
				RefreshToken:   loginResult.RefreshToken,
				OwnerUserID:    pendingRequest.User_id,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			})
			if err != nil {
				return
			}
			return
		}
	}
}

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

func HandlerGetFAccountState(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := protectedEndpointHandler(c)
		if result != 200 {
			return
		}

		userID, exists := c.Get("userID")
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
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		gameAccount, err := GetGameAccountByOwner(db, userUUID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Fortnite account not connected", "details": err.Error()})
			return
		}

		// Call Epic Games API to get incoming friend requests
		//friendRequests,
		_, friends, err := GetEpicFriendsState(gameAccount.AccessToken, gameAccount.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch Fortnite account state", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"username":        gameAccount.Username,
			"remaining_gifts": gameAccount.RemainingGifts,
			"friends":         friends,
			//"incoming_requests": friendRequests,
		})
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

	var list_ofPendingRequests []AccountsToConnect

	router := gin.Default()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(genericMiddleware)

	allowedOrigins := map[string]bool{
		"*":                                true,
		"http://localhost:5173":            true,
		"https://your-production-site.com": true,
	}

	router.Use(cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			return allowedOrigins[origin]
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"X-Total-Count"},
		AllowWildcard:    true,
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	gin.SetMode(gin.ReleaseMode)

	authorized := router.Group("/", AuthMiddleware())

	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome Gin Server")
	})

	authorized.POST("/addnewuser", HandlerAddNewUser(db))
	authorized.POST("/removeusers", HandlerRemoveUsers(db))
	authorized.POST("/updateuser", HandlerUpdateUser(db))
	authorized.POST("/connectfaccount", HandlerConnectFAccount(db, &list_ofPendingRequests))
	authorized.POST("/disconnectfortniteaccount", HandlerDisconnectFAccount(db))
	//authorized.GET("/faccountstate", HandlerGetFAccountState(db))
	//Falta: go routine para revisar periodicamente por solicitudes de amistad

	router.POST("/loginform", HandlerLoginForm(db, cfg.AdminUser))

	go UpdateTokensPeriodically(db, &list_ofPendingRequests)

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
