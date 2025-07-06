package utils

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Authorization header missing"})
			return
		}

		// Should be "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Authorization header format must be Bearer {token}"})
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
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid token", "details": err.Error()})
			return
		}

		// Extract userID from claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["user_id"] == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid token claims"})
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

func GenericMiddleware(c *gin.Context) {
	// Middleware logic here
	//Options for preflight requests
	if c.Request.Method == "OPTIONS" {
		c.JSON(http.StatusOK, nil)
		c.Abort()
		return
	}
	c.Next()
}

func AdminProtectedEndpointHandler(c *gin.Context) int {

	err := VerifyToken(c.Request.Header.Get("Authorization")[len("Bearer "):])
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid token", "details": err.Error()})
		return 401
	}
	return 200 // 200 OK
}

func ProtectedEndpointHandler(c *gin.Context) int {
	err := VerifyToken(c.Request.Header.Get("Authorization")[len("Bearer "):])
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Invalid token", "details": err.Error()})
		return 401
	}
	return 200 // 200 OK
}

func IsTokenAdmin(c *gin.Context) bool {
	tokenString := c.Request.Header.Get("Authorization")
	if tokenString == "" {
		return false
	}

	tokenString = tokenString[len("Bearer "):]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		return false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["admin"] == nil {
		return false
	}

	return claims["admin"].(bool)
}

func ProtectedHandler(c *gin.Context) {
	// This handler is protected by the AuthMiddleware
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "User ID not found in context"})
		return
	}

	// You can use userID for further processing
	fmt.Println("Protected handler accessed by user:", userID)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Welcome to the protected area", "userID": userID})
}
