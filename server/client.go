package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/websocket"
)

// Simple client for MVP testing: can register, listen, and send encrypted messages.

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func clampScalar(s []byte) []byte {
	// clone
	c := make([]byte, len(s))
	copy(c, s)
	c[0] &= 248
	c[31] &= 127
	c[31] |= 64
	return c
}

func genKeypair() (pub, priv []byte, err error) {
	privRaw, err := randBytes(32)
	if err != nil {
		return nil, nil, err
	}
	priv = clampScalar(privRaw)
	// basepoint
	basepoint := [32]byte{9}
	pub, err = curve25519.X25519(priv, basepoint[:])
	return pub, priv, err
}

func deriveRoot(ourPriv, theirPub []byte) ([]byte, error) {
	ss, err := curve25519.X25519(ourPriv, theirPub)
	if err != nil {
		return nil, err
	}
	hk := hkdf.New(sha256.New, ss, nil, []byte("CarrierBridgeRoot"))
	root := make([]byte, 32)
	if _, err := io.ReadFull(hk, root); err != nil {
		return nil, err
	}
	return root, nil
}

type RegisterReq struct {
	ID             string   `json:"id"`
	Phone          string   `json:"phone"`
	DisplayName    string   `json:"display_name"`
	IdentityPub    string   `json:"identity_pub"`
	SignedPrekey   string   `json:"signed_prekey"`
	OneTimePrekeys []string `json:"one_time_prekeys"`
}

type KeysResp struct {
	IdentityPub   string `json:"identity_pub"`
	SignedPrekey  string `json:"signed_prekey"`
	OneTimePrekey string `json:"one_time_prekey"`
}

type EnvelopeMessage struct {
	Type      string `json:"type"`
	MessageID string `json:"message_id"`
	SenderID  string `json:"sender_id"`
	Recipient string `json:"recipient"`
	Payload   []byte `json:"payload"`
	Timestamp int64  `json:"timestamp"`
}

func doRegister(server, id, phone, display string) (string, []byte, []byte, error) {
	idPub, idPriv, err := genKeypair()
	if err != nil {
		return "", nil, nil, err
	}
	spkPub, spkPriv, err := genKeypair()
	if err != nil {
		return "", nil, nil, err
	}
	otkPub, _, err := genKeypair()
	if err != nil {
		return "", nil, nil, err
	}

	req := RegisterReq{
		ID:             id,
		Phone:          phone,
		DisplayName:    display,
		IdentityPub:    base64.StdEncoding.EncodeToString(idPub),
		SignedPrekey:   base64.StdEncoding.EncodeToString(spkPub),
		OneTimePrekeys: []string{base64.StdEncoding.EncodeToString(otkPub)},
	}

	b, _ := json.Marshal(req)
	resp, err := http.Post(server+"/v1/register", "application/json", bytesReader(b))
	if err != nil {
		return "", nil, nil, err
	}
	defer resp.Body.Close()
	var r map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", nil, nil, err
	}
	token, _ := r["token"].(string)
	return token, idPriv, spkPriv, nil
}

// helper to make io.Reader from bytes
func bytesReader(b []byte) io.Reader { return &readerFromBytes{b, 0} }

type readerFromBytes struct {
	b []byte
	i int
}

func (r *readerFromBytes) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func dialWebsocket(server, token string) (*websocket.Conn, error) {
	u := server
	u = strings.ReplaceAll(u, "http://", "ws://")
	u = strings.ReplaceAll(u, "https://", "wss://")
	// attach token as query param for simple clients
	wsurl := u + "/ws?token=" + url.QueryEscape(token)
	config, err := websocket.NewConfig(wsurl, "http://localhost/")
	if err != nil {
		return nil, err
	}
	config.Header = http.Header{"Authorization": {"Bearer " + token}}
	conn, err := websocket.DialConfig(config)
	return conn, err
}

func encryptAndSend(conn *websocket.Conn, root []byte, sender, recipient, plaintext string) error {
	aead, err := chacha20poly1305.NewX(root)
	if err != nil {
		return err
	}
	nonce, _ := randBytes(chacha20poly1305.NonceSizeX)
	ct := aead.Seal(nil, nonce, []byte(plaintext), nil)
	// payload = nonce || ct
	payload := append(nonce, ct...)
	msg := EnvelopeMessage{
		Type:      "message",
		MessageID: base64.StdEncoding.EncodeToString(mustRand(8)),
		SenderID:  sender,
		Recipient: recipient,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}
	return websocket.JSON.Send(conn, msg)
}

func mustRand(n int) []byte {
	b, err := randBytes(n)
	if err != nil {
		panic(err)
	}
	return b
}

func testMain() {
	server := flag.String("server", "http://localhost:8080", "server base URL")
	id := flag.String("id", "alice", "local user id")
	action := flag.String("action", "listen", "action: register|listen|send")
	to := flag.String("to", "bob", "recipient id for send")
	token := flag.String("token", "", "auth token")
	msg := flag.String("msg", "Hello", "message to send")
	flag.Parse()

	switch *action {
	case "register":
		t, _, _, err := doRegister(*server, *id, "+1000000000", *id)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("token=%s\n", t)
	case "listen":
		if *token == "" {
			log.Fatal("token required to listen")
		}
		conn, err := dialWebsocket(*server, *token)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("connected, waiting for messages...")
		for {
			var incoming EnvelopeMessage
			if err := websocket.JSON.Receive(conn, &incoming); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("INBOUND from %s: %x bytes\n", incoming.SenderID, len(incoming.Payload))
		}
	case "send":
		if *token == "" {
			log.Fatal("token required to send")
		}
		// For demo: fetch recipient public key
		resp, err := http.Get(*server + "/v1/keys/" + *to)
		if err != nil {
			log.Fatal(err)
		}
		var kr KeysResp
		if err := json.NewDecoder(resp.Body).Decode(&kr); err != nil {
			log.Fatal(err)
		}
		resp.Body.Close()
		theirPub, _ := base64.StdEncoding.DecodeString(kr.IdentityPub)
		// generate ephemeral key
		_, ephPriv, err := genKeypair()
		if err != nil {
			log.Fatal(err)
		}
		root, err := deriveRoot(ephPriv, theirPub)
		if err != nil {
			log.Fatal(err)
		}
		conn, err := dialWebsocket(*server, *token)
		if err != nil {
			log.Fatal(err)
		}
		if err := encryptAndSend(conn, root, *id, *to, *msg); err != nil {
			log.Fatal(err)
		}
		fmt.Println("sent")
	default:
		log.Fatalf("unknown action: %s", *action)
	}
}
