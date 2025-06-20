package page

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/fortnite"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func HandlerLoginForm(db *sql.DB, adminUsername string, refreshList *types.RefreshList) gin.HandlerFunc {
	return func(c *gin.Context) {
		var form types.Login
		if err := c.ShouldBind(&form); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		//Get user from db
		dbuser, err := database.GetUserByUsername(db, form.User)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials", "details": err.Error()})
			return
		}
		if dbuser.Password == form.Password {
			//todo pick admin username from somewhre else. secret source.
			if dbuser.Username == adminUsername {
				tokenString, err := utils.CreateAdminToken(dbuser.Username, dbuser.ID.String())
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token", "details": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": tokenString})
				return
			} else {
				tokenString, err := utils.CreateToken(dbuser.Username, dbuser.ID.String())
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token", "details": err.Error()})
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": tokenString})
				fortnite.HandlerUpdatePavosBulk(db, refreshList)
				return
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Password"})

	}
}

// ============================ USER HANDLERS ============================

func HandlerAddNewUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		var newUser types.User
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if newUser.ID == uuid.Nil {
			newUser.ID = uuid.New()
		}
		newUser.CreatedAt = time.Now()
		newUser.UpdatedAt = time.Now()
		if err := database.AddUser(db, newUser); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not add new user", "details": err.Error()})
			return
		}
		c.String(http.StatusOK, "User added successfully")
	}
}

func HandlerGetAllUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		users, err := database.GetAllUsers(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch users", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, users)
	}
}

func HandlerRemoveUsers(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		//block deletion of admin account
		adminUser, err := database.GetUserByUsername(db, os.Getenv("ADMIN_USER"))
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

		errr := database.DeleteUsersByIds(db, ids)
		if errr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not remove users", "details": errr.Error()})
			return
		}
		c.String(http.StatusOK, "Users removed successfully")
	}
}

func HandlerUpdateUser(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.AdminProtectedEndpointHandler(c)
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

// endpoint to send all game accounts of the user
func HandlerGetGameAccountsByOwner(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
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

		var resultAccounts []types.SimplifiedAccount = []types.SimplifiedAccount{}
		for _, account := range gameAccounts {
			resultAccounts = append(resultAccounts, types.SimplifiedAccount{
				ID:             account.ID.String(),
				DisplayName:    account.DisplayName,
				Pavos:          0, // You can replace this with actual V-Bucks if you track them
				RemainingGifts: account.RemainingGifts,
			})
		}

		c.JSON(http.StatusOK, resultAccounts)
	}
}

func HandlerGetTransactions(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}
		rows, err := db.Query(`SELECT id, game_account_id, sender_name, receiver_id, receiver_username, object_store_id, object_store_name, regular_price, final_price, gift_image, created_at FROM transactions`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch transactions", "details": err.Error()})
			return
		}
		defer rows.Close()

		var transactions []types.Transaction
		for rows.Next() {
			var tx types.Transaction
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
		result := utils.AdminProtectedEndpointHandler(c)
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

func GetAllGameAccounts(db *sql.DB) ([]types.GameAccount, error) {
	var accounts []types.GameAccount
	rows, err := db.Query(`SELECT id, display_name, remaining_gifts, pavos, access_token, access_token_exp, access_token_exp_date, refresh_token, refresh_token_exp, refresh_token_exp_date FROM game_accounts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var account types.GameAccount
		if err := rows.Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.PaVos, &account.AccessToken, &account.AccessTokenExp, &account.AccessTokenExpDate, &account.RefreshToken, &account.RefreshTokenExp, &account.RefreshTokenExpDate); err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func GetGameAccountsByOwner(db *sql.DB, ownerUserID uuid.UUID) ([]types.GameAccount, error) {
	query := `SELECT id, display_name, remaining_gifts, access_token, refresh_token, created_at, updated_at FROM game_accounts WHERE owner_user_id = $1`
	rows, err := db.Query(query, ownerUserID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var accounts []types.GameAccount
	for rows.Next() {
		var account types.GameAccount

		err := rows.Scan(&account.ID, &account.DisplayName, &account.RemainingGifts, &account.AccessToken, &account.RefreshToken, &account.CreatedAt, &account.UpdatedAt)
		if err != nil {
			return nil, err
		}

		accounts = append(accounts, account)
	}
	return accounts, nil
}
