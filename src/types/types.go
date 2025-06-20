package types

import (
	"time"

	"github.com/google/uuid"
)

type AccountsToConnect struct {
	User_id     uuid.UUID `json:"user_id"`
	Device_code string    `json:"device_code"`
}

type Login struct {
	User     string `form:"user" json:"user" xml:"user" binding:"required"`
	Password string `form:"password" json:"password" xml:"password" binding:"required"`
}

type EnvConfigType struct {
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

type DeviceResultResponse struct {
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
	ID              uuid.UUID
	GameAccountID   uuid.UUID
	SenderName      *string
	ReceiverID      *string
	ReceiverName    *string
	ObjectStoreID   string
	ObjectStoreName string
	RegularPrice    float64
	FinalPrice      float64
	GiftImage       string
	CreatedAt       time.Time
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

type AccountTokens struct {
	ID             uuid.UUID
	AccessTokenExp time.Time
	RefreshToken   string
	AccessToken    string
}

type RefreshList map[uuid.UUID]AccountTokens

// Map to simplified response
type SimplifiedAccount struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	Pavos          int    `json:"pavos"`
	RemainingGifts int    `json:"remainingGifts"`
}

type PublicAccountResult struct {
	AccountId   string `json:"id"`
	DisplayName string `json:"displayName"`
}

type FriendResult struct {
	AccountId string `json:"accountId"`
	Alias     string `json:"alias"`
	Created   string `json:"created"`
}
