package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func HandlerSearchOnlineFortniteAccount(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		var req types.GameFriendRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
			return
		}

		AccountID, err := uuid.Parse(req.AccountId)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Invalid account ID format"})
			return
		}

		request, _ := http.NewRequest("GET", fmt.Sprintf("https://account-public-service-prod.ol.epicgames.com/account/api/public/account/displayName/%s", req.DisplayName), nil)

		resp, err := ExecuteOperationWithRefresh(request, db, AccountID, "friendSearch")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "No se encontro al usuario", "details": err.Error()})
			return
		}
		defer resp.Body.Close()

		var tokenResult types.PublicAccountResult
		if err := json.NewDecoder(resp.Body).Decode(&tokenResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "No se encontro al usuario.", "details": err.Error()})
			return
		}

		reqFriends, _ := http.NewRequest("GET", fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/friends/%s", req.AccountId, tokenResult.AccountId), nil)

		respFriends, err := ExecuteOperationWithRefresh(reqFriends, db, AccountID, "SearchFridnd")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Error interno", "details": err.Error()})
			return
		}
		defer respFriends.Body.Close()

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
				c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "El usuario no es amigo.", "details": err.Error()})
				return
			}
			// Check if the error code is "errors.com.epicgames.friends.friendship_not_found"
			if respFriends.StatusCode == 404 && errorResponse.ErrorCode == "errors.com.epicgames.friends.friendship_not_found" {
				c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "El usuario no esta en la lista de amigos", "details": errorResponse.ErrorMessage})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Could not get client token", "details": errorResponse.ErrorMessage})
			return
		}

		var friendResult types.FriendResult
		if err := json.NewDecoder(respFriends.Body).Decode(&friendResult); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Usuario no encontrado", "details": err.Error()})
			return
		}
		//check if the account is in the friends list for more than 48 hours
		//if friendResult.Created > 48 hours
		friendCreated, err := time.Parse(time.RFC3339, friendResult.Created)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Invalid friend created date", "details": err.Error()})
			return
		}
		if time.Since(friendCreated) > 48*time.Hour {

			//parse created to dd/mm/yyyy, hh:mm in gtm -5
			friendCreatedStr := friendCreated.Format("02/01/2006 15:04")
			friendCreatedStr = friendCreatedStr + " GMT-5"
			c.JSON(http.StatusOK, gin.H{"success": true, "giftable": true, "friend": true, "user": true, "accountId": tokenResult.AccountId, "displayName": tokenResult.DisplayName, "created": friendCreatedStr})
			return
		}

	}

}

// TODO
func getIncomingRequests(db *sql.DB, gameAccount types.GameAccount) ([]types.FriendRequest, error) {
	//parse gameAccount.ID to string

	AccountIDStr, err := utils.ConvertUUIDToString(gameAccount.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid game account ID: %w", err)
	}

	request, _ := http.NewRequest("GET", fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/incoming", AccountIDStr), nil)

	resp, err := ExecuteOperationWithRefresh(request, db, gameAccount.ID, "SearchFriend2")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get incoming friend requests, status: %d", resp.StatusCode)
	}

	var friendRequests []types.FriendRequest
	err = json.NewDecoder(resp.Body).Decode(&friendRequests)
	if err != nil {
		return nil, err
	}

	return friendRequests, nil

}

// TODO
func acceptFriendRequests(db *sql.DB, gameAccount types.GameAccount, friends []types.FriendRequest) error {
	AccountIDStr, err := utils.ConvertUUIDToString(gameAccount.ID)
	if err != nil {
		return fmt.Errorf("invalid game account ID: %w", err)
	}

	for _, friend := range friends {
		request, _ := http.NewRequest("GET", fmt.Sprintf("https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/%s/friends/%s", AccountIDStr, friend.AccountID), nil)
		resp, err := ExecuteOperationWithRefresh(request, db, gameAccount.ID, "acceptFriendRequest")
		if err != nil {
			fmt.Printf("Failed to accept friend request from %s: %v\n", friend.AccountID, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 204 || resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 202 {
			fmt.Printf("Accepted friend request from %s\n", friend.AccountID)
			continue
		}
		return fmt.Errorf("failed to accept friend request from %s, status: %d", friend.AccountID, resp.StatusCode)
	}
	return nil
}

// TODO
func StartFriendRequestHandler(db *sql.DB, intervalMinutes int) {
	//we are using the refresh list here as it should contain ALL the accounts registered in the db
	//this is a bit of a hack, but it works

	for {
		time.Sleep(time.Duration(intervalMinutes) * time.Minute)

		gameAccounts, err := database.GetAllGameAccounts(db)
		if err != nil {
			fmt.Printf("Error fetching game accounts: %v\n", err)
			continue
		}

		for _, account := range gameAccounts {
			//sleep for 1+random second to avoid rate limiting
			time.Sleep(time.Duration(rand.Float32()+0.2) * time.Second)
			friendRequests, err := getIncomingRequests(db, account)

			//remove - from the friend requests
			for i, friend := range friendRequests {
				friend.AccountID = strings.ReplaceAll(friend.AccountID, "-", "")
				friendRequests[i] = friend

				//print parsed friend request
				fmt.Printf("Parsed Friend Id: %+v\n", friend.AccountID)
			}
			//print friend requests again

			if err != nil {
				fmt.Printf("Failed to get friend requests for account %s: %v\n", account.DisplayName, err)
				continue
			}

			if len(friendRequests) > 0 {
				fmt.Println()
				err := acceptFriendRequests(db, account, friendRequests)
				if err != nil {
					fmt.Printf("Failed to accept friend requests for account %s: %v\n", account.DisplayName, err)
				} else {
					fmt.Printf("Accepted %d friend requests for account %s\n", len(friendRequests), account.DisplayName)
				}
			}
		}
	}
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
