package protocol

import (
    "encoding/json"
    "time"
)

type MessageType string

const (
    MessageTypeText    MessageType = "text"
    MessageTypeCall    MessageType = "call"
    MessageTypePayment MessageType = "payment"
    MessageTypeFile    MessageType = "file"
)

type SecureMessage struct {
    ID        string      `json:"id"`
    Type      MessageType `json:"type"`
    From      string      `json:"from"`
    To        string      `json:"to"`
    Content   string      `json:"content"`
    Timestamp time.Time   `json:"timestamp"`
    Signature string      `json:"signature,omitempty"`
}

type PaymentRequest struct {
    TransactionID string    `json:"transaction_id"`
    FromUser      string    `json:"from_user"`
    ToUser        string    `json:"to_user"`
    Amount        int64     `json:"amount"`
    Currency      string    `json:"currency"`
    Description   string    `json:"description"`
    Timestamp     time.Time `json:"timestamp"`
}

func (m *SecureMessage) Serialize() ([]byte, error) {
    return json.Marshal(m)
}

func (m *SecureMessage) Deserialize(data []byte) error {
    return json.Unmarshal(data, m)
}