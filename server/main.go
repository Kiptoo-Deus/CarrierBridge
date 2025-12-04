package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/gorilla/websocket"
)

var (
	addr       = flag.String("addr", ":8080", "HTTP service address")
	mpesaAPI   = flag.String("mpesa-api", "https://sandbox.safaricom.co.ke", "M-Pesa API endpoint")
	consumerKey = flag.String("consumer-key", "", "M-Pesa consumer key")
	consumerSecret = flag.String("consumer-secret", "", "M-Pesa consumer secret")
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type Message struct {
	Type      string    `json:"type"`      // "message", "payment", "ack"
	MessageID string    `json:"message_id"`
	SenderID  string    `json:"sender_id"`
	Recipient string    `json:"recipient"`
	Payload   []byte    `json:"payload"`
	Timestamp int64     `json:"timestamp"`
}

type PaymentRequest struct {
	Type         string `json:"type"` // "stk_push"
	PhoneNumber  string `json:"phone_number"`
	Amount       int    `json:"amount"`
	Reference    string `json:"reference"`
	Description  string `json:"description"`
	CallbackURL  string `json:"callback_url"`
}

type Client struct {
	ID     string
	Conn   *websocket.Conn
	Send   chan []byte
	Online bool
}

type Hub struct {
	mu      sync.RWMutex
	clients map[string]*Client
	queue   map[string][]Message // Offline message queue
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[string]*Client),
		queue:   make(map[string][]Message),
	}
}

// Database helper functions -------------------------------------------------

func ensureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			phone TEXT,
			display_name TEXT,
			identity_pub BLOB,
			signed_prekey BLOB,
			token TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS one_time_prekeys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id TEXT,
			prekey BLOB
		);`,
		`CREATE TABLE IF NOT EXISTS queued_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			recipient TEXT,
			sender TEXT,
			payload BLOB,
			type TEXT,
			message_id TEXT,
			timestamp INTEGER
		);`,
	}

	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

func genToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Simple user registration: stores identity keys and prekeys and returns a token
func registerUser(db *sql.DB, id, phone, displayName string, identityPub, signedPrekey []byte, oneTimePrekeys [][]byte) (string, error) {
	token, err := genToken()
	if err != nil {
		return "", err
	}

	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT OR REPLACE INTO users (id, phone, display_name, identity_pub, signed_prekey, token) VALUES (?, ?, ?, ?, ?, ?)`, id, phone, displayName, identityPub, signedPrekey, token)
	if err != nil {
		return "", err
	}

	// Insert one-time prekeys
	for _, pk := range oneTimePrekeys {
		if _, err := tx.Exec(`INSERT INTO one_time_prekeys (user_id, prekey) VALUES (?, ?)`, id, pk); err != nil {
			return "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

// Fetch and consume a single one-time prekey for a user (returns nil if none)
func fetchOneTimePrekey(db *sql.DB, userID string) ([]byte, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRow(`SELECT id, prekey FROM one_time_prekeys WHERE user_id = ? ORDER BY id LIMIT 1`, userID)
	var id int64
	var prekey []byte
	if err := row.Scan(&id, &prekey); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if _, err := tx.Exec(`DELETE FROM one_time_prekeys WHERE id = ?`, id); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return prekey, nil
}

func getUserByToken(db *sql.DB, token string) (string, error) {
	row := db.QueryRow(`SELECT id FROM users WHERE token = ?`, token)
	var id string
	if err := row.Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}


func (h *Hub) register(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[client.ID] = client
	client.Online = true
	
	log.Printf("[Hub] Client registered: %s", client.ID)
	
	// Deliver queued messages
	if queued, ok := h.queue[client.ID]; ok {
		log.Printf("[Hub] Delivering %d queued messages to %s", len(queued), client.ID)
		for _, msg := range queued {
			if data, err := json.Marshal(msg); err == nil {
				select {
				case client.Send <- data:
				default:
					log.Printf("[Hub] Failed to deliver queued message to %s", client.ID)
				}
			}
		}
		delete(h.queue, client.ID)
	}
}

func (h *Hub) unregister(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if client, ok := h.clients[id]; ok {
		client.Online = false
		close(client.Send)
		log.Printf("[Hub] Client unregistered: %s", id)
	}
	delete(h.clients, id)
}

func (h *Hub) send(id string, data []byte) bool {
	h.mu.RLock()
	client, ok := h.clients[id]
	h.mu.RUnlock()
	
	if ok && client.Online {
		select {
		case client.Send <- data:
			return true
		default:
			log.Printf("[Hub] Send channel full for %s", id)
			return false
		}
	}
	return false
}

func (h *Hub) queueMessage(msg Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.queue[msg.Recipient] = append(h.queue[msg.Recipient], msg)
	log.Printf("[Hub] Queued message for offline client: %s", msg.Recipient)
}

func (h *Hub) processMessage(data []byte) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("[Hub] Failed to unmarshal message: %v", err)
		return
	}
	
	msg.Timestamp = time.Now().Unix()
	
	// Handle payment requests
	if msg.Type == "payment" {
		var payment PaymentRequest
		if err := json.Unmarshal(msg.Payload, &payment); err == nil {
			go h.processPayment(payment, msg.SenderID)
		}
		return
	}
	
	// Try to send immediately
	msgData, _ := json.Marshal(msg)
	if !h.send(msg.Recipient, msgData) {
		// Queue for later delivery
		h.queueMessage(msg)
		log.Printf("[Hub] Message from %s to %s queued (offline)", msg.SenderID, msg.Recipient)
	} else {
		log.Printf("[Hub] Message delivered from %s to %s", msg.SenderID, msg.Recipient)
	}
}

func (h *Hub) processPayment(payment PaymentRequest, senderID string) {
	log.Printf("[Hub] Processing payment: %+v from %s", payment, senderID)
	
	// Simulate M-Pesa STK Push
	// In production, call actual M-Pesa API:
	// POST https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest
	// Headers: Authorization: Bearer <token>
	// Body: {
	//   "BusinessShortCode": "174379",
	//   "Password": "<encoded>",
	//   "Timestamp": "20191219102345",
	//   "TransactionType": "CustomerPayBillOnline",
	//   "Amount": "<amount>",
	//   "PartyA": "<phone>",
	//   "PartyB": "174379",
	//   "PhoneNumber": "<phone>",
	//   "CallBackURL": "<callback>",
	//   "AccountReference": "<reference>",
	//   "TransactionDesc": "<description>"
	// }
	
	time.Sleep(2 * time.Second)
	
	// Send payment confirmation
	response := map[string]interface{}{
		"type":        "payment_confirmation",
		"success":     true,
		"reference":   payment.Reference,
		"amount":      payment.Amount,
		"timestamp":   time.Now().Unix(),
		"description": "Payment processed successfully (simulated)",
	}
	
	responseData, _ := json.Marshal(response)
	
	msg := Message{
		Type:      "payment_ack",
		SenderID:  "server",
		Recipient: senderID,
		Payload:   responseData,
		Timestamp: time.Now().Unix(),
	}
	
	msgData, _ := json.Marshal(msg)
	if !h.send(senderID, msgData) {
		h.queueMessage(msg)
		log.Printf("[Hub] Payment ACK queued for %s", senderID)
	}
}

func serveWS(db *sql.DB, hub *Hub, w http.ResponseWriter, r *http.Request) {
	// Authenticate using Authorization header: Bearer <token>
	auth := r.Header.Get("Authorization")
	var token string
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token = strings.TrimSpace(auth[7:])
	} else {
		// fallback to token query param
		token = r.URL.Query().Get("token")
	}

	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	userID, err := getUserByToken(db, token)
	if err != nil || userID == "" {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[Hub] Upgrade error: %v", err)
		return
	}

	client := &Client{
		ID:   userID,
		Conn: conn,
		Send: make(chan []byte, 256),
	}

	// deliver persistent queued messages from DB
	rows, err := db.Query(`SELECT recipient, sender, payload, type, message_id, timestamp FROM queued_messages WHERE recipient = ? ORDER BY id`, userID)
	if err == nil {
		var msgs []Message
		for rows.Next() {
			var qm Message
			var ts int64
			if err := rows.Scan(&qm.Recipient, &qm.SenderID, &qm.Payload, &qm.Type, &qm.MessageID, &ts); err == nil {
				qm.Timestamp = ts
				msgs = append(msgs, qm)
			}
		}
		rows.Close()

		if len(msgs) > 0 {
			log.Printf("[Hub] Delivering %d persistent queued messages to %s", len(msgs), userID)
			for _, msg := range msgs {
				if data, err := json.Marshal(msg); err == nil {
					select {
					case client.Send <- data:
					default:
						log.Printf("[Hub] Failed to deliver persistent queued message to %s", userID)
					}
				}
			}
			// delete delivered queued messages
			if _, err := db.Exec(`DELETE FROM queued_messages WHERE recipient = ?`, userID); err != nil {
				log.Printf("[Hub] Failed to delete queued messages for %s: %v", userID, err)
			}
		}
	}

	hub.register(client)
	
	// Read pump
	go func() {
		defer func() {
			hub.unregister(id)
			conn.Close()
		}()
		
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err,
					websocket.CloseGoingAway,
					websocket.CloseAbnormalClosure) {
					log.Printf("[Hub] Read error: %v", err)
				}
				break
			}
			// Persist message if recipient offline
			var msg Message
			if err := json.Unmarshal(message, &msg); err == nil {
				if !hub.send(msg.Recipient, message) {
					// store persistently
					if _, err := db.Exec(`INSERT INTO queued_messages (recipient, sender, payload, type, message_id, timestamp) VALUES (?, ?, ?, ?, ?, ?)`, msg.Recipient, msg.SenderID, msg.Payload, msg.Type, msg.MessageID, time.Now().Unix()); err != nil {
						log.Printf("[Hub] Failed to persist queued message: %v", err)
					}
				}
			}
			hub.processMessage(message)
		}
	}()
	
	// Write pump
	go func() {
		defer conn.Close()
		
		for message := range client.Send {
			if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("[Hub] Write error: %v", err)
				break
			}
		}
	}()
}

func main() {
	flag.Parse()
    
	// Open DB
	dbPath := path.Join(".", "server.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Failed to open db: %v", err)
	}
	defer db.Close()

	if err := ensureSchema(db); err != nil {
		log.Fatalf("Failed to ensure schema: %v", err)
	}

	hub := NewHub()

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWS(db, hub, w, r)
	})

	// Registration endpoint
	http.HandleFunc("/v1/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		type registerReq struct {
			ID             string   `json:"id"`
			Phone          string   `json:"phone"`
			DisplayName    string   `json:"display_name"`
			IdentityPubB64 string   `json:"identity_pub"`
			SignedPrekeyB64 string  `json:"signed_prekey"`
			OneTimePrekeysB64 []string `json:"one_time_prekeys"`
		}

		var req registerReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		identityPub, _ := base64.StdEncoding.DecodeString(req.IdentityPubB64)
		signedPrekey, _ := base64.StdEncoding.DecodeString(req.SignedPrekeyB64)
		var otps [][]byte
		for _, s := range req.OneTimePrekeysB64 {
			if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
				otps = append(otps, b)
			}
		}

		token, err := registerUser(db, req.ID, req.Phone, req.DisplayName, identityPub, signedPrekey, otps)
		if err != nil {
			log.Printf("register error: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		resp := map[string]interface{}{"status": "ok", "id": req.ID, "token": token}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Keys endpoint: returns identity_pub, signed_prekey and a one-time prekey (consumed)
	http.HandleFunc("/v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user := path.Base(r.URL.Path)
		if user == "" || user == "keys" {
			http.Error(w, "missing user", http.StatusBadRequest)
			return
		}

		row := db.QueryRow(`SELECT identity_pub, signed_prekey FROM users WHERE id = ?`, user)
		var identityPub []byte
		var signedPrekey []byte
		if err := row.Scan(&identityPub, &signedPrekey); err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		opk, err := fetchOneTimePrekey(db, user)
		if err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}

		resp := map[string]interface{}{
			"identity_pub": base64.StdEncoding.EncodeToString(identityPub),
			"signed_prekey": base64.StdEncoding.EncodeToString(signedPrekey),
			"one_time_prekey": nil,
		}
		if opk != nil {
			resp["one_time_prekey"] = base64.StdEncoding.EncodeToString(opk)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().Unix(),
			"clients":   len(hub.clients),
		})
	})
	
	http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		hub.mu.RLock()
		defer hub.mu.RUnlock()
		
		queued_count := 0
		for _, msgs := range hub.queue {
			queued_count += len(msgs)
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"online_clients":  len(hub.clients),
			"queued_messages": queued_count,
			"timestamp":       time.Now().Unix(),
		})
	})
	
	log.Printf("Server starting on %s", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
