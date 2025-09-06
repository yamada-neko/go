package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type User struct {
    ID        int    `json:"id"`
    Name      string `json:"name"`
    Email     string `json:"email"`
    Password  string `json:"-"`
    CreatedAt string `json:"created_at"`
}

type Product struct {
    ID          int     `json:"id"`
    Name        string  `json:"name"`
    Description string  `json:"description"`
    Price       float64 `json:"price"`
    Stock       int     `json:"stock"`
    CreatedAt   string  `json:"created_at"`
}

func main() {
    var err error
    connStr := "user=postgres password=password dbname=ecsite sslmode=disable"
    db, err = sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal(err)
    }

    http.HandleFunc("/users", usersHandler)
    http.HandleFunc("/products", productsHandler)

    fmt.Println("Server running on http://localhost:3000")
    log.Fatal(http.ListenAndServe(":3000", nil))
}

/* --- ユーザー登録と取得 --- */
func usersHandler(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodPost:
        var u User
        if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
            http.Error(w, "invalid input", http.StatusBadRequest)
            return
        }
        hashed, _ := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)

        err := db.QueryRow(
            "INSERT INTO users (name, email, password) VALUES ($1,$2,$3) RETURNING id, name, email, created_at",
            u.Name, u.Email, string(hashed),
        ).Scan(&u.ID, &u.Name, &u.Email, &u.CreatedAt)
        if err != nil {
            http.Error(w, "failed to insert user", http.StatusInternalServerError)
            return
        }
        json.NewEncoder(w).Encode(u)

    case http.MethodGet:
        rows, err := db.Query("SELECT id, name, email, created_at FROM users")
        if err != nil {
            http.Error(w, "failed to fetch users", http.StatusInternalServerError)
            return
        }
        defer rows.Close()

        users := []User{}
        for rows.Next() {
            var u User
            rows.Scan(&u.ID, &u.Name, &u.Email, &u.CreatedAt)
            users = append(users, u)
        }
        json.NewEncoder(w).Encode(users)

    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
}

/* --- 商品登録と取得 --- */
func productsHandler(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodPost:
        var p Product
        if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
            http.Error(w, "invalid input", http.StatusBadRequest)
            return
        }
        err := db.QueryRow(
            "INSERT INTO products (name, description, price, stock) VALUES ($1,$2,$3,$4) RETURNING id, name, description, price, stock, created_at",
            p.Name, p.Description, p.Price, p.Stock,
        ).Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Stock, &p.CreatedAt)
        if err != nil {
            http.Error(w, "failed to insert product", http.StatusInternalServerError)
            return
        }
        json.NewEncoder(w).Encode(p)

    case http.MethodGet:
        rows, err := db.Query("SELECT id, name, description, price, stock, created_at FROM products ORDER BY created_at DESC")
        if err != nil {
            http.Error(w, "failed to fetch products", http.StatusInternalServerError)
            return
        }
        defer rows.Close()

        products := []Product{}
        for rows.Next() {
            var p Product
            rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Stock, &p.CreatedAt)
            products = append(products, p)
        }
        json.NewEncoder(w).Encode(products)

    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
}
