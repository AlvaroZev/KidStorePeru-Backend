package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func HandlerConnectFortniteAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		_, _, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": err})
		}

		client := &http.Client{Timeout: 10 * time.Second}
		authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte(utils.EpicClient+":"+utils.EpicSecret))

		// Step 1: Get client credentials token
		reqToken, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(
			"grant_type=client_credentials",
		))
		reqToken.Header.Set("Authorization", authHeader)
		reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		respToken, err := client.Do(reqToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not get client token", "details": err.Error()})
			return
		}
		defer respToken.Body.Close()

		var tokenResult types.AccessTokenResult
		if err := json.NewDecoder(respToken.Body).Decode(&tokenResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid client token response", "details": err.Error()})
			return
		}

		// Step 2: Request Device Auth URL
		reqDevice, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/deviceAuthorization", nil)
		reqDevice.Header.Set("Authorization", "bearer "+tokenResult.AccessToken)
		reqDevice.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		respDevice, err := client.Do(reqDevice)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not initiate device authorization", "details": err.Error()})
			return
		}
		defer respDevice.Body.Close()

		var deviceResult types.DeviceResultResponse
		if err := json.NewDecoder(respDevice.Body).Decode(&deviceResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid device authorization response", "details": err.Error()})
			return
		}

		// Step 2.1: Encode verification URI for direct redirect
		finalRedirect := url.QueryEscape(deviceResult.VerificationUriComplete)

		// Step 2.2: Embed directly in logout URL
		logoutURL := fmt.Sprintf("https://epicgames.com/id/logout?lang=en-US&redirectUrl=%s", finalRedirect)

		// Step 3: Send response
		c.JSON(http.StatusOK, gin.H{
			"success":                   true,
			"message":                   "Please complete Fortnite login",
			"verification_uri_complete": logoutURL,
			"epic_url":                  deviceResult.VerificationUriComplete,
			"user_code":                 deviceResult.UserCode,
			"device_code":               deviceResult.DeviceCode, // TODO: Encrypt this
			"expires_in":                deviceResult.Expires_in,
		})

	}
}

func HandlerFinishConnectFortniteAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		_, userIdUUID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": err})
		}

		var req types.DeviceCodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		client := &http.Client{Timeout: 10 * time.Second}
		authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte(utils.EpicClient+":"+utils.EpicSecret))

		reqToken, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(
			"grant_type=device_code&device_code="+req.DeviceCode,
		))
		reqToken.Header.Set("Authorization", authHeader)
		reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		respToken, err := client.Do(reqToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not Authorize user in step 1", "details": err.Error()})
			return
		}

		if respToken.StatusCode == 400 || respToken.StatusCode != 200 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid device code or expired", "details": respToken.Body, "status_code": respToken.StatusCode})
			return
		}

		defer respToken.Body.Close()

		var tokenResultStep1 types.LoginResultResponse
		if err := json.NewDecoder(respToken.Body).Decode(&tokenResultStep1); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid client token response", "details": err.Error()})
			return
		}

		// //print all
		// fmt.Println("Response Status Code:", respToken.StatusCode)
		// fmt.Println("Response Headers:", respToken.Header)
		// fmt.Println("Response Body:", respToken.Body)

		// //print all request
		// fmt.Println("Request Method:", reqToken.Method)
		// fmt.Println("Request URL:", reqToken.URL)
		// fmt.Println("Request Headers:", reqToken.Header)
		// fmt.Println("Request Body:", reqToken.Body)
		// fmt.Println("Parsed content", tokenResultStep1)

		//step 2, get Secret and Device Id
		reqSecrets, _ := http.NewRequest("POST", fmt.Sprintf("https://account-public-service-prod.ol.epicgames.com/account/api/public/account/%s/deviceAuth", tokenResultStep1.AccountId), nil)
		reqSecrets.Header.Set("Authorization", "Bearer "+tokenResultStep1.AccessToken)

		respSecrets, err := client.Do(reqSecrets)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not get device secrets", "details": err.Error()})
			return
		}
		defer respSecrets.Body.Close()
		var deviceSecrets types.DeviceSecretsResponse
		if err := json.NewDecoder(respSecrets.Body).Decode(&deviceSecrets); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid device secrets response", "details": err.Error()})
			return
		}

		//PRINT ALL DEVICE SECRETS
		//fmt.Println("Device Secrets Status Code:", respSecrets.StatusCode)
		//parse the device secrets
		var deviceSecretsParsed = types.GameAccountSecrets{
			DeviceId:  deviceSecrets.DeviceId,
			AccountId: tokenResultStep1.AccountId,
			Secret:    deviceSecrets.Secret,
		}

		// Step 3: device auth with secret and device id
		loginResult, err := DeviceAuthIdGrant(db, deviceSecretsParsed)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not get device auth ID", "details": err.Error()})
			return
		}

		//store the account in the database
		AccountID, err := uuid.Parse(loginResult.AccountId)
		if err != nil {
			fmt.Println("Failed to parse game ID:", err)
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid account ID format", "details": err.Error()})
			return
		}

		//save the game account
		err = database.AddGameAccount(db, types.GameAccount{
			ID:                  AccountID,
			DisplayName:         loginResult.DisplayName,
			RemainingGifts:      5,
			PaVos:               0,
			AccessToken:         loginResult.AccessToken,
			AccessTokenExp:      loginResult.AccessTokenExpiration,
			AccessTokenExpDate:  time.Now().Add(time.Duration(loginResult.AccessTokenExpiration) * time.Second),
			RefreshToken:        loginResult.RefreshToken,
			RefreshTokenExp:     loginResult.RefreshTokenExpiration,
			RefreshTokenExpDate: time.Now().Add(time.Duration(loginResult.RefreshTokenExpiration) * time.Second),
			OwnerUserID:         userIdUUID,
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		})
		if err != nil {
			fmt.Println("Error saving game account:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not save game account", "details": err.Error()})
			return
		}

		// Save device secrets in the database
		err = database.AddGameAccountSecrets(db, types.GameAccountSecrets{
			Owner_user_id: userIdUUID,
			DeviceId:      deviceSecrets.DeviceId,
			AccountId:     deviceSecrets.AccountId,
			Secret:        deviceSecrets.Secret,
		})
		if err != nil {
			fmt.Println("Error saving game account secrets:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not save game account secrets", "details": err.Error()})
			// delete the game account if we can't save the secrets
			_ = database.DeleteGameAccountByID(db, AccountID)
			return
		}

		//get account pavos
		pavos, err := GetAccountPavos(db, AccountID)
		if err != nil {
			pavos = 0 // Default to 0 if we can't fetch
			fmt.Printf("Could not fetch account pavos, defaulting to 0: %v\n", err)
		}

		//save the game account pavos
		err = database.UpdateGameAccount(db, types.GameAccount{
			ID:    AccountID,
			PaVos: pavos,
		})
		if err != nil {
			fmt.Println("Error saving game account:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not save game account", "details": err.Error()})
			//dont delete the game account if we can't save the pavos
			//_ = database.DeleteGameAccountByID(db, AccountID)
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Fortnite account connected successfully", "id": loginResult.AccountId, "username": loginResult.DisplayName, "pavos": pavos})
	}

}

// device auth with secret and device id
func DeviceAuthIdGrant(db *sql.DB, deviceSecrets types.GameAccountSecrets) (types.LoginResultResponse, error) {
	//running id grant with device id and secret
	client := &http.Client{Timeout: 10 * time.Second}
	authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte(utils.EpicClient+":"+utils.EpicSecret))

	reqDeviceAuth, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(
		"grant_type=device_auth&device_id="+deviceSecrets.DeviceId+"&secret="+deviceSecrets.Secret+"&account_id="+deviceSecrets.AccountId,
	))
	reqDeviceAuth.Header.Set("Authorization", authHeader)
	reqDeviceAuth.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	respDeviceAuth, err := client.Do(reqDeviceAuth)
	if err != nil {
		return types.LoginResultResponse{}, fmt.Errorf("could not get device auth ID: %w", err)
	}
	defer respDeviceAuth.Body.Close()

	if respDeviceAuth.StatusCode != 200 {
		return types.LoginResultResponse{}, fmt.Errorf("unexpected status code: %d", respDeviceAuth.StatusCode)
	}

	var loginResult types.LoginResultResponse
	if err := json.NewDecoder(respDeviceAuth.Body).Decode(&loginResult); err != nil {
		return types.LoginResultResponse{}, fmt.Errorf("invalid device auth ID response: %w", err)
	}

	return loginResult, nil
}

func HandlerAuthorizationCodeLogin(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		_, userIdUUID, err := utils.GetUserIdFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": err})
		}

		var req types.AuthorizationCode
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		client := &http.Client{Timeout: 10 * time.Second}
		authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte(utils.EpicClient+":"+utils.EpicSecret))

		reqToken, _ := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(
			fmt.Sprintf("grant_type=authorization_code&code=%s", req.Code),
		))
		reqToken.Header.Set("Authorization", authHeader)
		reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		respToken, err := client.Do(reqToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not get client token", "details": err.Error()})
			return
		}
		defer respToken.Body.Close()

		var tokenResult types.LoginResultResponse
		if err := json.NewDecoder(respToken.Body).Decode(&tokenResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid client token response", "details": err.Error()})
			return
		}
		gameId, err := uuid.Parse(tokenResult.AccountId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid game account ID", "details": err.Error()})
			return
		}
		if gameId == uuid.Nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid game account ID"})
			return
		}

		//get account pavos
		pavos, err := GetAccountPavos(db, gameId)
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
			OwnerUserID:         userIdUUID,
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not save game account", "details": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Fortnite account connected successfully", "id": tokenResult.AccountId, "username": tokenResult.DisplayName})
	}
}

func RefreshAccessToken(refreshToken string, db *sql.DB) (types.LoginResultResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	authHeader := "basic " + base64.StdEncoding.EncodeToString([]byte(utils.EpicClient+":"+utils.EpicSecret))

	reqToken, err := http.NewRequest("POST", "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token", strings.NewReader(
		//fmt.Sprint("grant_type=refresh_token&refresh_token=%s", refreshToken),
		fmt.Sprintf("grant_type=refresh_token&refresh_token=%s", url.QueryEscape(refreshToken)),
	))
	if err != nil {
		return types.LoginResultResponse{}, fmt.Errorf("could not create request for token refresh: %w", err)
	}
	reqToken.Header.Set("Authorization", authHeader)
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	respToken, err := client.Do(reqToken)
	if err != nil {
		return types.LoginResultResponse{}, fmt.Errorf("could not refresh access token: %w", err)
	}

	defer respToken.Body.Close()

	var tokenResult types.LoginResultResponse
	err = json.NewDecoder(respToken.Body).Decode(&tokenResult)
	if err != nil {
		return types.LoginResultResponse{}, err
	}

	if respToken.StatusCode != 200 {
		return types.LoginResultResponse{}, fmt.Errorf("unexpected status code: %d, response: %s", respToken.StatusCode, respToken.Body)
	}

	//print response
	fmt.Println("Token result:", tokenResult)

	//UPDATE DB
	AccountId, err := uuid.Parse(tokenResult.AccountId)
	if err != nil {
		fmt.Printf("Failed to parse game ID.: %v", err)
		return types.LoginResultResponse{}, err
	}

	err = database.UpdateGameAccount(db, types.GameAccount{
		ID:                  AccountId,
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

func ExecuteOperationWithRefresh(request *http.Request, db *sql.DB, GameAccountID uuid.UUID, source string) (*http.Response, error) {
	//pavosSource := source == "pavos"

	GameAccount, err := database.GetGameAccount(db, GameAccountID)
	if err != nil {
		fmt.Printf("Could not get game account tokens for %s: %v\n", GameAccountID, err)
		return nil, fmt.Errorf("could not get game account tokens: %s", err)
	}
	//print source
	fmt.Printf("Executing operation for account %s with source %s\n", GameAccountID, source)

	// Set appropriate header
	if source == "pavos" {
		fmt.Printf("Using Pavo source for account %s\n and access token %s", GameAccountID, GameAccount.AccessToken)
		request.Header.Set("Cookie", fmt.Sprintf("EPIC_BEARER_TOKEN=%s; cf_clearance=jlaoO7IXOwEipJ48ixVck2DxwPn9YUeA64GiwNCeg4M-1757486839-1.2.1.1-4msbjWuU_pEWUHd2RqZprQ9_cdkEzFVe5oTXJx9cnFxP6OQqwRX_MOIohhe8nhr5mvNPrhV1gxcbaGpmvG7clUFlTnaz0rPbZhm_JXlnXZQe5Reu.c.eoGbKrS2U8O51cV2S9.VzCfC8TkdoC9WarJ2hxprttfV2gKqrZp8eAAMaI7l.8pc41bS6s9bS2_JAU9xvqPU.5Lj9gKBNni9d9Alh1MWQKWAeSOWNCyBeFOM", GameAccount.AccessToken))
		// //request.Header.Set("User-Agent", "PostmanRuntime/7.44.1")
		//keep alive
		request.Header.Set("Connection", "keep-alive")
		//accept encoding
		request.Header.Set("Accept-Encoding", "identity")
		//accept
		// //request.Header.Set("Accept", "*/*")

		request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36")
		request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		request.Header.Set("Accept-Language", "en-US,en;q=0.5")
	} else {
		fmt.Printf("Using standard source for account %s\n and access token %s", GameAccountID, GameAccount.AccessToken)
		request.Header.Set("Authorization", "Bearer "+GameAccount.AccessToken)
	}

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		fmt.Printf("Initial request execution failed for account %s: %v\n", GameAccountID, err)
		return nil, fmt.Errorf("request execution failed: %s", err)
	}
	//print response status code and body
	fmt.Printf("Response Status Code: %d\n", resp.StatusCode)
	if resp.Body != nil {

		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Failed to read response body for account %s: %v\n", GameAccountID, err)
			return nil, fmt.Errorf("could not read response body: %w", err)
		}
		//do not print response body if source is gift
		if source != "gift" {
			fmt.Printf("Response Body: %s\n", string(bodyBytes))
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Reset body for further reads
	} else {
		fmt.Printf("Response Body is nil for account %s\n", GameAccountID)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		fmt.Printf("Access token expired or unauthorized for account %s, attempting refresh\n", GameAccountID)

		newTokens, err := RefreshAccessToken(GameAccount.RefreshToken, db)
		if err == nil {
			fmt.Printf("Access token refresh successful for account %s\n", GameAccountID)
			err = database.UpdateGameAccount(db, types.GameAccount{
				ID:                  GameAccount.ID,
				AccessToken:         newTokens.AccessToken,
				AccessTokenExp:      newTokens.AccessTokenExpiration,
				AccessTokenExpDate:  time.Now().Add(time.Duration(newTokens.AccessTokenExpiration) * time.Second),
				RefreshToken:        newTokens.RefreshToken,
				RefreshTokenExp:     newTokens.RefreshTokenExpiration,
				RefreshTokenExpDate: time.Now().Add(time.Duration(newTokens.RefreshTokenExpiration) * time.Second),
				UpdatedAt:           time.Now(),
			})
			if err != nil {
				fmt.Printf("Failed to update game account with refreshed tokens for account %s: %v\n", GameAccount.ID, err)
				return nil, fmt.Errorf("could not update game account with new tokens: %w", err)
			}

			// Retry with new token
			if source == "pavos" {
				request.Header.Set("Cookie", fmt.Sprintf("EPIC_BEARER_TOKEN=%s; cf_clearance=999282", newTokens.AccessToken))
			} else {
				request.Header.Set("Authorization", "Bearer "+newTokens.AccessToken)
			}

			resp, err = client.Do(request)
			if err != nil {
				fmt.Printf("Retry request after token refresh failed for account %s: %v\n", GameAccount.ID, err)
				return nil, fmt.Errorf("retry request execution failed: %s", err)
			}
			return resp, nil
		}

		// Token refresh via refresh token failed
		fmt.Printf("RefreshAccessToken failed for account %s: %v\n", GameAccount.ID, err)

		GameAccountStr, err := utils.ConvertUUIDToString(GameAccount.ID)
		if err != nil {
			fmt.Printf("Failed to convert GameAccount ID to string: %v\n", err)
			return nil, fmt.Errorf("invalid game account ID: %w", err)
		}
		if GameAccountStr == "" {
			fmt.Println("Game account ID is empty after conversion")
			return nil, fmt.Errorf("game account ID is empty")
		}

		deviceSecrets, err := database.GetGameAccountSecrets(db, GameAccountStr)
		if err != nil {
			fmt.Printf("Could not get device secrets for account %s: %v\n", GameAccountStr, err)
			return nil, fmt.Errorf("could not get device secrets: %w", err)
		}
		fmt.Printf("Device Secrets for %s: %+v\n", GameAccountStr, deviceSecrets)

		newTokens, err = DeviceAuthIdGrant(db, deviceSecrets)
		if err != nil {
			fmt.Printf("DeviceAuthIdGrant failed for account %s: %v\n", GameAccountStr, err)
			return nil, fmt.Errorf("could not refresh access token using device auth: %w", err)
		}

		err = database.UpdateGameAccount(db, types.GameAccount{
			ID:                  GameAccount.ID,
			AccessToken:         newTokens.AccessToken,
			AccessTokenExp:      newTokens.AccessTokenExpiration,
			AccessTokenExpDate:  time.Now().Add(time.Duration(newTokens.AccessTokenExpiration) * time.Second),
			RefreshToken:        newTokens.RefreshToken,
			RefreshTokenExp:     newTokens.RefreshTokenExpiration,
			RefreshTokenExpDate: time.Now().Add(time.Duration(newTokens.RefreshTokenExpiration) * time.Second),
			UpdatedAt:           time.Now(),
		})
		if err != nil {
			fmt.Printf("Could not update game account with new tokens after device auth for account %s: %v\n", GameAccount.ID, err)
			return nil, fmt.Errorf("could not update game account with new tokens: %w", err)
		}

		// Retry request again with new token
		if source == "pavos" {
			request.Header.Set("Cookie", fmt.Sprintf("EPIC_BEARER_TOKEN=%s; cf_clearance=999282", newTokens.AccessToken))
		} else {
			request.Header.Set("Authorization", "Bearer "+newTokens.AccessToken)
		}

		resp, err = client.Do(request)
		if err != nil {
			fmt.Printf("Retry request after device auth failed for account %s: %v\n", GameAccount.ID, err)
			return nil, fmt.Errorf("retry request execution failed: %w", err)
		}
		return resp, nil
	}

	return resp, nil
}

func HandlerDisconnectFAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req struct {
			Id string `json:"id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		err := database.DeleteGameAccountByID(db, uuid.MustParse(req.Id))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not disconnect Fortnite account", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Fortnite account disconnected successfully"})
	}
}
