package fortnite

import (
	database "KidStoreBotBE/src/db"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func HandlerUpdatePavosBulk(db *sql.DB, refreshList *types.RefreshList) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
		if result != 200 {
			return
		}

		for accountID, Tokens := range *refreshList {

			//get the pavos from the account
			pavos, err := GetAccountPavos(Tokens.AccessToken)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Could not get PaVos for account %s: %s", accountID, err.Error())})
				return
			}

			//update the pavos in the database
			err = database.UpdatePaVos(db, accountID, pavos)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Could not update PaVos for account %s: %s", accountID, err.Error())})
				return
			}
			fmt.Printf("Updated PaVos for account %s: %d\n", accountID, pavos)

		}

	}
}

// func HandlerUpdatePavosBulk(db *sql.DB, refreshList *RefreshList) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		result := utils.ProtectedEndpointHandler(c)
// 		if result != 200 {
// 			return
// 		}

// 		var req struct {
// 			Accounts []string `json:"accounts" binding:"required"`
// 		}
// 		if err := c.ShouldBindJSON(&req); err != nil {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 			return
// 		}
// 		if len(req.Accounts) == 0 {
// 			c.JSON(http.StatusBadRequest, gin.H{"error": "No accounts provided"})
// 			return
// 		}

// 		for _, accountIDStr := range req.Accounts {
// 			//parse the account ID
// 			accountID, err := uuid.Parse(accountIDStr)
// 			if err != nil {
// 				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid account ID format: %s", accountIDStr)})
// 				return
// 			}
// 			//get the access token from the refresh list
// 			accessToken := (*refreshList)[accountID].AccessToken
// 			if err != nil {
// 				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Could not get access token for account %s: %s", accountIDStr, err.Error())})
// 				return
// 			}
// 			//get the pavos from the account
// 			pavos, err := GetAccountPavos(accessToken)
// 			if err != nil {
// 				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Could not get PaVos for account %s: %s", accountIDStr, err.Error())})
// 				return
// 			}

// 			//update the pavos in the database
// 			err = UpdatePaVos(db, accountID, pavos)
// 			if err != nil {
// 				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Could not update PaVos for account %s: %s", accountIDStr, err.Error())})
// 				return
// 			}
// 			fmt.Printf("Updated PaVos for account %s: %d\n", accountIDStr, pavos)

// 		}

// 	}
// }

func GetAccountPavos(acces_token string) (int, error) {
	client := &http.Client{Timeout: 20 * time.Second}

	req, err := http.NewRequest("GET", "https://www.epicgames.com/account/v2/api/wallet/fortnite", nil)
	if err != nil {
		return 0, fmt.Errorf("could not create request: %w", err)
	}
	//set cookieEPIC_BEARER_TOKEN=acces_token
	req.Header.Set("Cookie", fmt.Sprintf("EPIC_BEARER_TOKEN=%s", acces_token))
	req.Header.Set("User-Agent", "EpicGamesLauncher/14.6.2-14746003+++Portal+Release-Live Windows/10.0.19044.1.256.64bit")
	req.Header.Set("Accept", "application/json")
	//print request for debugging
	fmt.Println("Request URL:", req.URL.String())
	fmt.Println("Request Headers:", req.Header)

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("could not send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	var response struct {
		Success bool `json:"success"`
		Data    struct {
			Wallet struct {
				Purchased []struct {
					Type   string `json:"type"`
					Values struct {
						Shared  int `json:"Shared"`
						Switch  int `json:"Switch"`
						PCKorea int `json:"PCKorea"`
					} `json:"values"`
				} `json:"purchased"`
				Earned int `json:"earned"`
			} `json:"wallet"`
			LastUpdated string `json:"lastUpdated"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0, fmt.Errorf("could not decode response: %w", err)
	}
	if !response.Success {
		return 0, fmt.Errorf("API call was not successful")
	}
	pavos := 0
	for _, purchase := range response.Data.Wallet.Purchased {
		if purchase.Type == "Currency:MtxPurchased" {
			pavos += purchase.Values.Shared
		} else if purchase.Type == "Currency:MtxPurchaseBonus" {
			pavos += purchase.Values.Shared
		}
	}

	if pavos < 0 {
		return 0, fmt.Errorf("negative PaVos value received: %d", pavos)
	}
	return pavos, nil
}

// endpoint handler to send gift
func HandlerSendGift(db *sql.DB, refreshList *types.RefreshList) gin.HandlerFunc {
	return func(c *gin.Context) {
		result := utils.ProtectedEndpointHandler(c)
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

		//check if account has enough gifts
		remainingGifts, err := database.GetRemainingGifts(db, AccountId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch remaining gifts", "details": err.Error()})
			return
		}
		if remainingGifts <= 0 {
			c.JSON(http.StatusForbidden, gin.H{"error": "You have no gifts left to send"})
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

		err = database.AddTransaction(db, types.Transaction{
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

		//update the sender's PaVos
		err = SmartUpdatePavos(db, AccountId, -req.GiftPrice) // Decrease by the gift price
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update sender's PaVos", "details": err.Error()})
			return
		}

		// Update the sender's remaining gifts
		err = database.UpdateRemainingGifts(db, AccountId, remainingGifts-1) // Decrease by 1
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update remaining gifts", "details": err.Error()})
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

func SmartUpdatePavos(db *sql.DB, accountID uuid.UUID, pavos int) error {
	currentPavos, err := database.GetPavos(db, accountID)
	if err != nil {
		return fmt.Errorf("could not get current PaVos: %w", err)
	}

	if pavos < 0 && currentPavos+pavos < 0 {
		return fmt.Errorf("not enough PaVos to deduct")
	}

	newPavos := currentPavos + pavos
	if newPavos < 0 {
		newPavos = 0 // Ensure PaVos don't go negative
	}

	return database.UpdatePaVos(db, accountID, newPavos)

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

// ============================ FORTNITE ACCOUNT HANDLERS ============================
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
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := database.DeleteGameAccountByID(db, uuid.MustParse(req.Id))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not disconnect Fortnite account", "details": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Fortnite account disconnected successfully"})
	}
}

func UpdateRemainingGiftsInAccounts(db *sql.DB) error {
	//sleep for 15 minutes
	time.Sleep(15 * time.Minute)
	// Get all game account IDs
	accountIDs, err := database.GetAllGameAccountsIds(db)
	if err != nil {
		return fmt.Errorf("could not get game account IDs: %w", err)
	}

	//fetch the last 24 hours transactions
	transactions, err := database.GetLast24HoursTransactions(db)
	if err != nil {
		return fmt.Errorf("could not fetch transactions: %w", err)
	}

	//make 6 lists, each one has accounts ids with 0, 1, 2, 3, 4, 5 remaining gifts from the max 5 each 24 hours.
	var accountsWithZeroGifts []uuid.UUID
	var accountsWithOneGift []uuid.UUID
	var accountsWithTwoGifts []uuid.UUID
	var accountsWithThreeGifts []uuid.UUID
	var accountsWithFourGifts []uuid.UUID
	var accountsWithFiveGifts []uuid.UUID

	for _, tx := range accountIDs {
		var remainingGifts int
		for _, transaction := range transactions {
			if transaction.GameAccountID == tx {
				remainingGifts++
			}
		}

		switch remainingGifts {
		case 0:
			accountsWithZeroGifts = append(accountsWithZeroGifts, tx)
		case 1:
			accountsWithOneGift = append(accountsWithOneGift, tx)
		case 2:
			accountsWithTwoGifts = append(accountsWithTwoGifts, tx)
		case 3:
			accountsWithThreeGifts = append(accountsWithThreeGifts, tx)
		case 4:
			accountsWithFourGifts = append(accountsWithFourGifts, tx)
		case 5:
			accountsWithFiveGifts = append(accountsWithFiveGifts, tx)
		default:
			fmt.Printf("Account %s has more than 5 gifts in the last 24 hours\n", tx.String())
		}
	}

	// Update remaining gifts in bulk
	if err := database.UpdateRemainingGiftsInBulk(db, accountsWithZeroGifts, 0); err != nil {
		return fmt.Errorf("could not update accounts with zero gifts: %w", err)
	}
	if err := database.UpdateRemainingGiftsInBulk(db, accountsWithOneGift, 1); err != nil {
		return fmt.Errorf("could not update accounts with one gift: %w", err)
	}
	if err := database.UpdateRemainingGiftsInBulk(db, accountsWithTwoGifts, 2); err != nil {
		return fmt.Errorf("could not update accounts with two gifts: %w", err)
	}
	if err := database.UpdateRemainingGiftsInBulk(db, accountsWithThreeGifts, 3); err != nil {
		return fmt.Errorf("could not update accounts with three gifts: %w", err)
	}
	if err := database.UpdateRemainingGiftsInBulk(db, accountsWithFourGifts, 4); err != nil {
		return fmt.Errorf("could not update accounts with four gifts: %w", err)
	}
	if err := database.UpdateRemainingGiftsInBulk(db, accountsWithFiveGifts, 5); err != nil {
		return fmt.Errorf("could not update accounts with five gifts: %w", err)
	}
	return nil

}
