package main

import (
    "bufio"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "log"
    "net"
    "os"
    "strings"
    "time"

    "securecomm/platform/pkg/protocol"
)

type SecureCommClient struct {
    conn     net.Conn
    username string
    broker   string
}

func NewSecureCommClient(username, broker string) *SecureCommClient {
    return &SecureCommClient{
        username: username,
        broker:   broker,
    }
}

func (c *SecureCommClient) Connect() error {
    conn, err := tls.Dial("tcp", c.broker, &tls.Config{
        InsecureSkipVerify: true, // For development only
    })
    if err != nil {
        return err
    }
    c.conn = conn
    
    // Register with broker
    registerMsg := protocol.SecureMessage{
        ID:        generateID(),
        Type:      protocol.MessageTypeText,
        From:      c.username,
        To:        "broker",
        Content:   "REGISTER",
        Timestamp: time.Now(),
    }
    
    data, err := registerMsg.Serialize()
    if err != nil {
        return err
    }
    
    _, err = c.conn.Write(data)
    return err
}

func (c *SecureCommClient) SendMessage(recipient, content string) error {
    msg := protocol.SecureMessage{
        ID:        generateID(),
        Type:      protocol.MessageTypeText,
        From:      c.username,
        To:        recipient,
        Content:   content,
        Timestamp: time.Now(),
    }
    
    data, err := msg.Serialize()
    if err != nil {
        return err
    }
    
    _, err = c.conn.Write(data)
    return err
}

func (c *SecureCommClient) Listen() {
    scanner := bufio.NewScanner(c.conn)
    for scanner.Scan() {
        var msg protocol.SecureMessage
        if err := msg.Deserialize(scanner.Bytes()); err != nil {
            log.Printf("Error parsing message: %v", err)
            continue
        }
        fmt.Printf("\n[%s] %s: %s\n> ", msg.Timestamp.Format("15:04:05"), msg.From, msg.Content)
    }
}

func generateID() string {
    return fmt.Sprintf("%d", time.Now().UnixNano())
}

func main() {
    if len(os.Args) < 2 {
        log.Fatal("Usage: client <username> [broker_address]")
    }

    username := os.Args[1]
    broker := "localhost:55000"
    if len(os.Args) > 2 {
        broker = os.Args[2]
    }

    client := NewSecureCommClient(username, broker)
    if err := client.Connect(); err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer client.conn.Close()

    fmt.Printf("Connected as %s to %s\n", username, broker)
    fmt.Println("Type messages as: <recipient> <message>")

    go client.Listen()

    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" {
            continue
        }

        parts := strings.SplitN(line, " ", 2)
        if len(parts) < 2 {
            fmt.Println("Usage: <recipient> <message>")
            continue
        }

        if err := client.SendMessage(parts[0], parts[1]); err != nil {
            log.Printf("Failed to send message: %v", err)
        }
    }
}