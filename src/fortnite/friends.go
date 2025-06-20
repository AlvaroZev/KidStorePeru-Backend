package fortnite

import (
	"KidStoreBotBE/src/types"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

func getIncomingRequests(client *http.Client, account types.AccountTokens, db *sql.DB, refreshList *types.RefreshList) ([]types.FriendRequest, error) {
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

	var friendRequests []types.FriendRequest
	err = json.NewDecoder(resp.Body).Decode(&friendRequests)
	if err != nil {
		return nil, err
	}

	return friendRequests, nil

}

func acceptFriendRequests(client *http.Client, db *sql.DB, account types.AccountTokens, friends []types.FriendRequest, refreshList *types.RefreshList) error {
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

func StartFriendRequestHandler(db *sql.DB, intervalMinutes int, refreshList *types.RefreshList) {
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
