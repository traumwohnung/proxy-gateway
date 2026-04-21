package client

import (
	http "github.com/sardanioss/http"
)

// HookType represents the type of hook
type HookType string

const (
	// HookPreRequest is called before the request is sent
	HookPreRequest HookType = "pre_request"
	// HookPostResponse is called after the response is received
	HookPostResponse HookType = "post_response"
)

// PreRequestHook is called before a request is sent
// It receives the http.Request and can modify it
// Return an error to abort the request
type PreRequestHook func(req *http.Request) error

// PostResponseHook is called after a response is received
// It receives the Response and can inspect/modify it
// Return an error to signal a problem (won't affect the response)
type PostResponseHook func(resp *Response) error

// Hooks holds request hooks
type Hooks struct {
	preRequest   []PreRequestHook
	postResponse []PostResponseHook
}

// NewHooks creates a new Hooks instance
func NewHooks() *Hooks {
	return &Hooks{
		preRequest:   make([]PreRequestHook, 0),
		postResponse: make([]PostResponseHook, 0),
	}
}

// OnPreRequest adds a pre-request hook
// Hook is called before each request is sent
// Can be used to modify headers, log requests, etc.
func (h *Hooks) OnPreRequest(hook PreRequestHook) *Hooks {
	h.preRequest = append(h.preRequest, hook)
	return h
}

// OnPostResponse adds a post-response hook
// Hook is called after each response is received
// Can be used to log responses, collect metrics, etc.
func (h *Hooks) OnPostResponse(hook PostResponseHook) *Hooks {
	h.postResponse = append(h.postResponse, hook)
	return h
}

// RunPreRequest runs all pre-request hooks
func (h *Hooks) RunPreRequest(req *http.Request) error {
	if h == nil {
		return nil
	}
	for _, hook := range h.preRequest {
		if err := hook(req); err != nil {
			return err
		}
	}
	return nil
}

// RunPostResponse runs all post-response hooks
func (h *Hooks) RunPostResponse(resp *Response) error {
	if h == nil {
		return nil
	}
	for _, hook := range h.postResponse {
		if err := hook(resp); err != nil {
			return err
		}
	}
	return nil
}

// Clear removes all hooks
func (h *Hooks) Clear() {
	h.preRequest = make([]PreRequestHook, 0)
	h.postResponse = make([]PostResponseHook, 0)
}

// ClearPreRequest removes all pre-request hooks
func (h *Hooks) ClearPreRequest() {
	h.preRequest = make([]PreRequestHook, 0)
}

// ClearPostResponse removes all post-response hooks
func (h *Hooks) ClearPostResponse() {
	h.postResponse = make([]PostResponseHook, 0)
}
