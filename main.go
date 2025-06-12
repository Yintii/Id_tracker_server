package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

var jwtSecret = []byte("supersecretkey123") // TODO: Store securely!

func main() {
	var err error
	db, err = sql.Open("postgres", "postgres://yintii:Lennon231@localhost:5432/id_tracker_db?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	router := gin.Default()

	router.POST("/login", loginHandler)

	router.GET("/protected", AuthMiddleWare(), func(c *gin.Context) {
		userID := c.MustGet("user_id")
		email := c.MustGet("email")
		role := c.MustGet("role")

		c.JSON(http.StatusOK, gin.H{
			"message": "Protected Data",
			"user_id": userID,
			"email":   email,
			"role":    role,
		})
	})

	router.POST("/check_id", CheckIDHandler)

	log.Println("Server running on :8080")
	router.Run(":8080")
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Patron struct {
	FirstName     string `json:"first_name"`
	MiddleName    string `json:"middle_name"`
	LastName      string `json:"last_name"`
	DOB           string `json:"dob"` // Expected format: DDMMYYYY
	LicenseNumber string `json:"license_number"`
  State         string `json:"state"`
  Expiration    string `json:"expiration"`
  Gender        string `json:"gender"`
  Zipcode       string `json:"zipcode"`
}

// Fixed CheckIDHandler using Gin's context
func CheckIDHandler(c *gin.Context) {
	var p Patron
	if err := c.BindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON: " + err.Error()})
		return
	}

	fmt.Printf("Parsed Patron: %+v\n", p)

	dob, err := time.Parse("01022006", p.DOB)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format, expected DDMMYYYY"})
		return
	}

	query := `
    WITH ins AS (
      INSERT INTO patrons (first_name, middle_name, last_name, date_of_birth, license_number, state, expiration, gender, zipcode)
      VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (license_number) DO NOTHING
      RETURNING id
    )
    SELECT id FROM ins
    UNION
    SELECT id FROM patrons WHERE license_number = $5
    LIMIT 1;
  `

	var id int
	err = db.QueryRow(query, p.FirstName, p.MiddleName, p.LastName, dob, p.LicenseNumber, p.State, p.Expiration, p.Gender, p.Zipcode).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":      id,
		"message": "Patron Accepted",
	})
}

func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var passwordHash string
	var role string
	var userID int

	err := db.QueryRow("SELECT id, password_hash, role FROM users WHERE email = $1", req.Email).Scan(&userID, &passwordHash, &role)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	} else if err != nil {
		log.Println("DB error:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"email":   req.Email,
		"role":    role,
		"exp":     time.Now().Add(72 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"role":  role,
	})
}

func RoleMiddleWare(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get("role")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "role not found"})
			return
		}

		role, ok := roleVal.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Invalid role format"})
			return
		}

		for _, allowed := range allowedRoles {
			if role == allowed {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Access denied"})
	}
}

func AuthMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing auth header"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid auth header format"})
			return
		}

		tokenStr := parts[1]

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("user_id", claims["user_id"])
			c.Set("email", claims["email"])
			c.Set("role", claims["role"])
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "could not parse claims"})
			return
		}

		c.Next()
	}
}

