// ec-backend-main.go
// Simple EC-style backend in one file (Go + Gin + GORM + PostgreSQL)
// Usage:
// 1) Create a .env file (example below)
// 2) go mod init example.com/ec && go get && go run .
// .env example:
// DATABASE_DSN=host=localhost user=postgres password=secret dbname=ec_db port=5432 sslmode=disable TimeZone=Asia/Tokyo
// JWT_SECRET=supersecretkey
// PORT=8080

package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var jwtSecret []byte

// Models
type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `json:"name"`
	Email     string    `gorm:"email" gorm:"uniqueIndex"`
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type Product struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Price       int64     `json:"price"` // cents
	Stock       int64     `json:"stock"`
	CreatedAt   time.Time `json:"created_at"`
}

type Order struct {
	ID        uint        `gorm:"primaryKey" json:"id"`
	UserID    uint        `json:"user_id"`
	User      User        `gorm:"foreignKey:UserID" json:"-"`
	Total     int64       `json:"total"` // cents
	Items     []OrderItem `json:"items" gorm:"constraint:OnDelete:CASCADE"`
	Address   string      `json:"address"`
	CreatedAt time.Time   `json:"created_at"`
}

type OrderItem struct {
	ID        uint    `gorm:"primaryKey" json:"id"`
	OrderID   uint    `json:"order_id"`
	ProductID uint    `json:"product_id"`
	Product   Product `gorm:"foreignKey:ProductID" json:"product"`
	Quantity  int64   `json:"quantity"`
	UnitPrice int64   `json:"unit_price"` // snapshot price
}

// DTOs
type RegisterDTO struct {
	Name     string `json:"name" binding:"required"`
	Email     string    `json:"email" gorm:"uniqueIndex"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginDTO struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type ProductDTO struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	Price       int64  `json:"price" binding:"required"`
	Stock       int64  `json:"stock" binding:"required"`
}

type PurchaseItemDTO struct {
	ProductID uint  `json:"product_id" binding:"required"`
	Quantity  int64 `json:"quantity" binding:"required,gt=0"`
}

type PurchaseDTO struct {
	Items   []PurchaseItemDTO `json:"items" binding:"required,dive,required"`
	Address string            `json:"address" binding:"required"`
}

// JWT claims
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

func main() {
	loadEnv()
	initDB()

	r := gin.Default()

	api := r.Group("/api")
	{
		api.POST("/register", registerHandler)
		api.POST("/login", loginHandler)

		api.GET("/products", listProductsHandler)
		api.GET("/products/:id", getProductHandler)

		// protected
		apiAuth := api.Group("")
		apiAuth.Use(authMiddleware())
		{
			apiAuth.POST("/products", createProductHandler)
			apiAuth.POST("/purchase", purchaseHandler)
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("listening on :%s", port)
	r.Run(":" + port)
}

func loadEnv() {
	_ = godotenv.Load()
	jwtSecret = []byte(getEnv("JWT_SECRET", "dev-secret"))
}

func initDB() {
	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		log.Fatal("DATABASE_DSN env required, see .env.example")
	}
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect db: %v", err)
	}

	// migrations
	err = db.AutoMigrate(&User{}, &Product{}, &Order{}, &OrderItem{})
	if err != nil {
		log.Fatalf("migration failed: %v", err)
	}
}

func registerHandler(c *gin.Context) {
	var dto RegisterDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	user := User{Name: dto.Name, Email: strings.ToLower(dto.Email), Password: string(hashed)}
	if err := db.Create(&user).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email already registered"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": user.ID, "email": user.Email, "name": user.Name})
}

func loginHandler(c *gin.Context) {
	var dto LoginDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("email = ?", strings.ToLower(dto.Email)).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(dto.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// create token
	claims := &Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": s})
}

func createProductHandler(c *gin.Context) {
	var dto ProductDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	p := Product{Name: dto.Name, Description: dto.Description, Price: dto.Price, Stock: dto.Stock}
	if err := db.Create(&p).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create product"})
		return
	}
	c.JSON(http.StatusCreated, p)
}

func listProductsHandler(c *gin.Context) {
	var products []Product
	if err := db.Find(&products).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch products"})
		return
	}
	c.JSON(http.StatusOK, products)
}

func getProductHandler(c *gin.Context) {
	id := c.Param("id")
	var p Product
	if err := db.First(&p, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "product not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

func purchaseHandler(c *gin.Context) {
	userID := c.GetUint("user_id")
	var dto PurchaseDTO
	if err := c.ShouldBindJSON(&dto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// transaction
	err := db.Transaction(func(tx *gorm.DB) error {
		var total int64 = 0
		var items []OrderItem
		for _, it := range dto.Items {
			var p Product
			if err := tx.Clauses().First(&p, it.ProductID).Error; err != nil {
				return fmt.Errorf("product %d not found", it.ProductID)
			}
			if p.Stock < it.Quantity {
				return fmt.Errorf("not enough stock for product %d", it.ProductID)
			}
			// decrease stock
			if err := tx.Model(&Product{}).Where("id = ? AND stock >= ?", p.ID, it.Quantity).UpdateColumn("stock", gorm.Expr("stock - ?", it.Quantity)).Error; err != nil {
				return fmt.Errorf("failed to update stock for product %d", p.ID)
			}
			item := OrderItem{ProductID: p.ID, Quantity: it.Quantity, UnitPrice: p.Price}
			items = append(items, item)
			total += p.Price * it.Quantity
		}

		order := Order{UserID: userID, Total: total, Items: items, Address: dto.Address}
		if err := tx.Create(&order).Error; err != nil {
			return errors.New("failed to create order")
		}
		return nil
	})

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "purchase successful"})
}

// Auth middleware
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
			return
		}
		tokenStr := parts[1]
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})
		if err != nil || !tkn.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("user_id", claims.UserID)
		c.Next()
	}
}

// helpers
func getEnv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
