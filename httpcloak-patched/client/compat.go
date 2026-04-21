package client

import (
	"fmt"
	"os"
)

// HeadersFromMap converts the old map[string]string header format to the new
// map[string][]string format. This is provided for backward compatibility.
//
// Deprecated: Use map[string][]string directly for headers. This function
// will be removed in a future version.
//
// Example migration:
//
//	// Old (deprecated):
//	headers := map[string]string{"Content-Type": "application/json"}
//
//	// New:
//	headers := map[string][]string{"Content-Type": {"application/json"}}
func HeadersFromMap(old map[string]string) map[string][]string {
	fmt.Fprintln(os.Stderr, "httpcloak: DEPRECATION WARNING - map[string]string headers are deprecated.")
	fmt.Fprintln(os.Stderr, "           Please use map[string][]string instead.")
	fmt.Fprintln(os.Stderr, "           Example: map[string][]string{\"Content-Type\": {\"application/json\"}}")

	if old == nil {
		return nil
	}

	headers := make(map[string][]string, len(old))
	for k, v := range old {
		headers[k] = []string{v}
	}
	return headers
}

// H is a shorthand for creating single-value headers.
// Use this for convenience when you only need one value per header.
//
// Example:
//
//	headers := client.H{
//	    "Content-Type": "application/json",
//	    "Accept": "application/json",
//	}
//	req := &client.Request{
//	    URL: "https://example.com",
//	    Headers: headers.ToMulti(),
//	}
type H map[string]string

// ToMulti converts H to map[string][]string for use with Request.Headers
func (h H) ToMulti() map[string][]string {
	if h == nil {
		return nil
	}
	result := make(map[string][]string, len(h))
	for k, v := range h {
		result[k] = []string{v}
	}
	return result
}

// MakeHeaders creates a map[string][]string from key-value pairs.
// Useful for inline header creation.
//
// Example:
//
//	headers := client.MakeHeaders("Content-Type", "application/json", "Accept", "text/html")
func MakeHeaders(keyValuePairs ...string) map[string][]string {
	if len(keyValuePairs)%2 != 0 {
		panic("MakeHeaders: odd number of arguments, expected key-value pairs")
	}

	headers := make(map[string][]string, len(keyValuePairs)/2)
	for i := 0; i < len(keyValuePairs); i += 2 {
		key := keyValuePairs[i]
		value := keyValuePairs[i+1]
		headers[key] = append(headers[key], value)
	}
	return headers
}
