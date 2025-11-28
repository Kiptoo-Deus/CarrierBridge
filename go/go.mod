module securecomm/platform

go 1.22.1

require (
    google.golang.org/grpc v1.58.0
    google.golang.org/protobuf v1.31.0
    github.com/gorilla/websocket v1.5.0
    github.com/sirupsen/logrus v1.9.3
    golang.org/x/crypto v0.14.0
)

// For local development, we'll replace with our local proto files
replace securecomm/core => ../core