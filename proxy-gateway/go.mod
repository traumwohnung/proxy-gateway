module proxy-gateway

go 1.26.1

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/go-chi/chi/v5 v5.2.5
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
	proxy-kit v0.0.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/sardanioss/http v1.2.0 // indirect
	github.com/sardanioss/httpcloak v1.6.1 // indirect
	github.com/sardanioss/net v1.2.5 // indirect
	github.com/sardanioss/qpack v0.6.3 // indirect
	github.com/sardanioss/quic-go v1.2.23 // indirect
	github.com/sardanioss/udpbara v1.1.0 // indirect
	github.com/sardanioss/utls v1.10.3 // indirect
	github.com/ua-parser/uap-go v0.0.0-20251207011819-db9adb27a0b8 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)

replace proxy-kit => ../proxy-kit

replace github.com/sardanioss/httpcloak => ../httpcloak-patched
