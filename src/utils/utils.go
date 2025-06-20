package utils

import (
	"KidStoreBotBE/src/types"
	"database/sql"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

var secretKey = []byte("secret-key")

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

func VerifyToken(tokenString string) error {
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

func NestTokensInRefreshList(db *sql.DB, refreshList *types.RefreshList) {
	// Get all game accounts from the database
	rows, err := db.Query(`SELECT id, access_token, access_token_exp_date, refresh_token FROM game_accounts`)
	if err != nil {
		fmt.Printf("Error fetching game accounts: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var account types.AccountTokens
		if err := rows.Scan(&account.ID, &account.AccessToken, &account.AccessTokenExp, &account.RefreshToken); err != nil {
			fmt.Printf("Error scanning game account: %v", err)
			continue
		}
		//convert account.ID to string
		accountId := account.ID.String()

		//print accountId and account.ID
		fmt.Printf("Account ID: %s, Account ID (UUID): %s\n", accountId, account.ID.String())
		(*refreshList)[account.ID] = types.AccountTokens{
			ID:             account.ID,
			AccessToken:    account.AccessToken,
			RefreshToken:   account.RefreshToken,
			AccessTokenExp: account.AccessTokenExp,
		}

	}
}
