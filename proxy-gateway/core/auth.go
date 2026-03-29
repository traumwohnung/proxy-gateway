package core

import (
	"context"
	"fmt"
)

// Authenticator validates a caller's identity and credential.
type Authenticator interface {
	Authenticate(identity, credential string) error
}

// Auth is middleware that validates Identity(ctx) and Credential(ctx)
// before delegating to the next handler.
func Auth(auth Authenticator, next Handler) Handler {
	return HandlerFunc(func(ctx context.Context, req *Request) (*Result, error) {
		if err := auth.Authenticate(Identity(ctx), Credential(ctx)); err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
		return next.Resolve(ctx, req)
	})
}
