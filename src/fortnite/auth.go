package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func HandlerSearchOnlineFortniteAccount(db *sql.DB, refreshList *types.RefreshList) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
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

		var tokenResult types.PublicAccountResult
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

		var friendResult types.FriendResult
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
func HandlerRefreshToken(db *sql.DB, refreshList *types.RefreshList) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
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

		// Update the refresh list with the new tokens
		(*refreshList)[AccountId] = types.AccountTokens{
			ID:             AccountId,
			AccessTokenExp: time.Now().Add(time.Duration(newTokens.AccessTokenExpiration) * time.Second),
			RefreshToken:   newTokens.RefreshToken,
			AccessToken:    newTokens.AccessToken,
		}

		c.JSON(http.StatusOK, gin.H{"message": "Access token refreshed successfully", "newAccessToken": newTokens.AccessToken})
	}
}

type deviceResultResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationUriComplete string `json:"verification_uri_complete"`
	Expires_in              int    `json:"expires_in"`
}

func HandlerConnectFAccount(db *sql.DB, list_ofPendingRequests *[]types.AccountsToConnect) gin.HandlerFunc {
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

		var tokenResult types.AccessTokenResult
		if err := json.NewDecoder(respToken.Body).Decode(&tokenResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid client token response", "details": err.Error()})
			return
		}

		//print access code of request 1
		fmt.Println("Access Token of 1:", tokenResult.AccessToken)

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

		// Print the device code and user code
		fmt.Println("Device Code 2:", deviceResult.DeviceCode)
		fmt.Println("User Code 2:", deviceResult.UserCode)

		// Step 3: Send login URL back to user
		c.JSON(http.StatusOK, gin.H{
			"message":                   "Please complete Fortnite login",
			"verification_uri_complete": deviceResult.VerificationUriComplete,
			"user_code":                 deviceResult.UserCode,
			"expires_in":                deviceResult.Expires_in,
		})
		pending_request := types.AccountsToConnect{
			User_id:     userUUID,
			Device_code: deviceResult.DeviceCode,
		}
		*list_ofPendingRequests = append(*list_ofPendingRequests, pending_request)

	}
}

func UpdateTokensPeriodically(db *sql.DB, list_ofPendingRequests *[]types.AccountsToConnect) {
	for {
		time.Sleep(30 * time.Second) // wait before polling again
		fmt.Println("Polling for tokens...")

		if len(*list_ofPendingRequests) == 0 {
			return
		}
		for i := 0; i < len(*list_ofPendingRequests); i++ {
			pendingRequest := (*list_ofPendingRequests)[i]

			fmt.Println("Polling for each token...")
			reqPoll, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(
				"grant_type=device_code&device_code="+pendingRequest.Device_code,
			))
			//authHeaderf := "basic " + base64.StdEncoding.EncodeToString([]byte("98f7e42c2e3a4f86a74eb43fbb41ed39:0a2449a2-001a-451e-afec-3e812901c4d7"))
			//authHeaderf := "basic " + base64.StdEncoding.EncodeToString([]byte("ec684b8c687f479fadea3cb2ad83f5c6:e1f31c211f28413186262d37a13fc84d")) //new key
			authHeaderf := "basic " + base64.StdEncoding.EncodeToString([]byte("3f69e56c7649492c8cc29f1af08a8a12:b51ee9cb12234f50a69efa67ef53812e"))

			reqPoll.Header.Set("Authorization", authHeaderf)
			reqPoll.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			client := &http.Client{Timeout: 10 * time.Second}

			respPoll, err := client.Do(reqPoll)
			if err != nil {
				fmt.Println("Error during token polling:", err)
				continue
			}
			defer respPoll.Body.Close()

			if respPoll.StatusCode == 400 || respPoll.StatusCode != 200 {
				continue
			}

			var loginResult types.LoginResultResponse
			if err := json.NewDecoder(respPoll.Body).Decode(&loginResult); err != nil {
				fmt.Println("Error decoding response:", err)
				continue
			}

			AccountID, err := uuid.Parse(loginResult.AccountId)
			if err != nil {
				fmt.Println("Failed to parse game ID:", err)
				continue
			}

			// Save account info to DB
			//print access code of request 4 (repeats)
			fmt.Println("Access Token of 4:", loginResult.AccessToken)
			fmt.Println("Refresh Token of 4:", loginResult.RefreshToken)
			fmt.Println("GameAccountID of 4:", loginResult.AccountId)
			err = database.AddGameAccount(db, types.GameAccount{
				ID:                  AccountID,
				DisplayName:         loginResult.DisplayName,
				RemainingGifts:      0,
				PaVos:               0,
				AccessToken:         loginResult.AccessToken,
				AccessTokenExp:      loginResult.AccessTokenExpiration,
				AccessTokenExpDate:  time.Now().Add(time.Duration(loginResult.AccessTokenExpiration) * time.Second),
				RefreshToken:        loginResult.RefreshToken,
				RefreshTokenExp:     loginResult.RefreshTokenExpiration,
				RefreshTokenExpDate: time.Now().Add(time.Duration(loginResult.RefreshTokenExpiration) * time.Second),
				OwnerUserID:         pendingRequest.User_id,
				CreatedAt:           time.Now(),
				UpdatedAt:           time.Now(),
			})
			if err != nil {
				fmt.Println("Error saving game account:", err)
				continue
			}

			// Optional: remove the processed request from the list
			*list_ofPendingRequests = append((*list_ofPendingRequests)[:i], (*list_ofPendingRequests)[i+1:]...)
			i-- // adjust index after removing
		}

	}
}

func HandlerAuthorizationCodeLogin(db *sql.DB, refreshList *types.RefreshList) gin.HandlerFunc {
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
		//authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte("ec684b8c687f479fadea3cb2ad83f5c6:e1f31c211f28413186262d37a13fc84d"))
		authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte("3f69e56c7649492c8cc29f1af08a8a12:b51ee9cb12234f50a69efa67ef53812e"))

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

		var tokenResult types.LoginResultResponse
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

		//get account pavos
		pavos, err := GetAccountPavos(tokenResult.AccessToken)
		if err != nil {
			pavos = 0 // Default to 0 if we can't fetch
			fmt.Printf("Could not fetch account pavos, defaulting to 0: %v\n", err)
		}

		err = database.AddGameAccount(db, types.GameAccount{
			ID:                  gameId,
			DisplayName:         tokenResult.DisplayName,
			RemainingGifts:      5,
			PaVos:               pavos,
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
		(*refreshList)[AccountId] = types.AccountTokens{
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

func refreshAccessToken(client *http.Client, refreshToken string, refreshList *types.RefreshList, db *sql.DB) (types.LoginResultResponse, error) {
	form := url.Values{}
	//authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte("ec684b8c687f479fadea3cb2ad83f5c6:e1f31c211f28413186262d37a13fc84d"))
	authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte("3f69e56c7649492c8cc29f1af08a8a12:b51ee9cb12234f50a69efa67ef53812e"))

	form.Add("grant_type", "refresh_token")
	form.Add("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return types.LoginResultResponse{}, err
	}

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return types.LoginResultResponse{}, err
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
				err := database.DeleteGameAccountByID(db, accountId)
				if err != nil {
					fmt.Printf("Failed to delete game account from DB: %v", err)
					return types.LoginResultResponse{}, fmt.Errorf("removed account %s from DB due to token refresh failure\n", accountId)
				}
				fmt.Printf("Removed account %s from DB due to token refresh failure\n", accountId)
				return types.LoginResultResponse{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			}
		}
	}

	var tokenResult types.LoginResultResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResult)
	if err != nil {
		return types.LoginResultResponse{}, err
	}

	AccountId, err := uuid.Parse(tokenResult.AccountId)
	if err != nil {
		fmt.Printf("Failed to parse game ID: %v", err)
		return types.LoginResultResponse{}, err
	}

	//UPDATE refreshList
	(*refreshList)[AccountId] = types.AccountTokens{
		ID:             AccountId,
		AccessTokenExp: time.Now().Add(time.Duration(tokenResult.AccessTokenExpiration) * time.Second),
		RefreshToken:   tokenResult.RefreshToken,
		AccessToken:    tokenResult.AccessToken,
	}

	//UPDATE DB
	gameId, err := uuid.Parse(tokenResult.AccountId)
	if err != nil {
		fmt.Printf("Failed to parse game ID: %v", err)
		return types.LoginResultResponse{}, err
	}

	err = database.UpdateGameAccount(db, types.GameAccount{
		ID:                  gameId,
		DisplayName:         tokenResult.DisplayName,
		AccessToken:         tokenResult.AccessToken,
		AccessTokenExp:      tokenResult.AccessTokenExpiration,
		AccessTokenExpDate:  time.Now().Add(time.Duration(tokenResult.AccessTokenExpiration) * time.Second),
		RefreshToken:        tokenResult.RefreshToken,
		RefreshTokenExp:     tokenResult.RefreshTokenExpiration,
		RefreshTokenExpDate: time.Now().Add(time.Duration(tokenResult.RefreshTokenExpiration) * time.Second),
		UpdatedAt:           time.Now(),
	})
	if err != nil {
		fmt.Printf("Failed to update token in DB: %v", err)
		return types.LoginResultResponse{}, err
	}

	return tokenResult, nil
}

// loop, check if token is less than 15 minutes away from expiring, if so, refresh it
func StartTokenRefresher(db *sql.DB, refreshList *types.RefreshList) {
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
