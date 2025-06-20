package main

import (
	"KidStoreBotBE/src/fortnite"
	page "KidStoreBotBE/src/page"
	"KidStoreBotBE/src/types"
	"KidStoreBotBE/src/utils"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

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
	var cfg types.EnvConfigType
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

	var refreshTokenList types.RefreshList = make(types.RefreshList)
	var list_ofPendingRequests []types.AccountsToConnect = make([]types.AccountsToConnect, 0)

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

	router.Use(utils.GenericMiddleware)

	gin.SetMode(gin.ReleaseMode)

	authorized := router.Group("/", utils.AuthMiddleware())
	authorized.Use(utils.GenericMiddleware)

	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Welcome Gin Server")
	})

	authorized.GET("/protected", func(ctx *gin.Context) {
		result := utils.ProtectedEndpointHandler(ctx)
		if result != 200 {
			return
		}

		// If the token is valid, proceed with the request to refresh pavos
		fortnite.HandlerUpdatePavosBulk(db, &refreshTokenList)
		ctx.JSON(http.StatusOK, gin.H{"message": "Welcome to the protected area"})
	})

	//login endpoint
	router.POST("/loginform", page.HandlerLoginForm(db, cfg.AdminUser, &refreshTokenList))

	//user endpoints
	authorized.POST("/addnewuser", page.HandlerAddNewUser(db))
	authorized.POST("/removeusers", page.HandlerRemoveUsers(db))
	authorized.POST("/updateuser", page.HandlerUpdateUser(db))
	authorized.GET("/getalluser", page.HandlerGetAllUsers(db))
	authorized.GET("/fortniteaccountsofuser", page.HandlerGetGameAccountsByOwner(db))
	authorized.GET("/allfortniteaccounts", page.HandlerGetAllGameAccounts(db))

	//fortnite account endpoints
	authorized.POST("/disconnectfortniteaccount", fortnite.HandlerDisconnectFAccount(db))
	//authorized.GET("/faccountstate", fortnite.HandlerGetFAccountState(db))
	authorized.POST("/connectfaccount", fortnite.HandlerAuthorizationCodeLogin(db, &refreshTokenList))
	authorized.POST("/sendGift", fortnite.HandlerSendGift(db, &refreshTokenList))
	authorized.POST("/searchfortnitefriend", fortnite.HandlerSearchOnlineFortniteAccount(db, &refreshTokenList))
	authorized.POST("/updatepavos", fortnite.HandlerUpdatePavosBulk(db, &refreshTokenList))
	//fetch transactions
	authorized.GET("/transactions", page.HandlerGetTransactions(db))
	//common
	utils.NestTokensInRefreshList(db, &refreshTokenList)

	//temp
	authorized.POST("/forcerefresh", fortnite.HandlerRefreshToken(db, &refreshTokenList))
	authorized.POST("/connectfortniteaccount", fortnite.HandlerConnectFAccount(db, &list_ofPendingRequests))

	//go StartFriendRequestHandler(db, cfg.AcceptFriendsInMinutes, &refreshTokenList) // Check every 5 minutes
	go fortnite.StartTokenRefresher(db, &refreshTokenList)            // Check every 10 minutes
	go fortnite.UpdateRemainingGiftsInAccounts(db)                    // Check every 15 minutes
	go fortnite.UpdateTokensPeriodically(db, &list_ofPendingRequests) // Check every 5 minutes

	router.Run(":8080")
}
