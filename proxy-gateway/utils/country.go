package utils

import (
	"fmt"
	"strings"
)

// Country is a two-letter country code used by proxy providers.
type Country string

func (c Country) AsParamStr() string { return strings.ToLower(string(c)) }

func (c *Country) UnmarshalTOML(data interface{}) error {
	s, ok := data.(string)
	if !ok {
		return fmt.Errorf("country must be a string")
	}
	*c = Country(strings.ToUpper(s))
	return nil
}

func (c *Country) UnmarshalJSON(data []byte) error {
	*c = Country(strings.ToUpper(strings.Trim(string(data), `"`)))
	return nil
}
