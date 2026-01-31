package crooner

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Sentinel errors for state encoding/decoding.
var (
	ErrInvalidStateFormat = errors.New("invalid state format")
	ErrInvalidStateData   = errors.New("invalid state data")
)

// EncodeStatePayload produces the OAuth state value. Format is base64(csrfState|originalPath).
func EncodeStatePayload(csrfState, originalPath string) string {
	if originalPath == "" {
		originalPath = "/"
	}
	stateData := csrfState + "|" + originalPath
	return base64.StdEncoding.EncodeToString([]byte(stateData))
}

// DecodeStatePayload decodes the OAuth state to extract the original path for post-auth redirect.
// State format is base64(csrfState|originalPath).
func DecodeStatePayload(state string) (originalPath string, err error) {
	stateBytes, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return "", errors.Join(ErrInvalidStateFormat, err)
	}
	stateParts := strings.SplitN(string(stateBytes), "|", 2)
	if len(stateParts) != 2 {
		return "", ErrInvalidStateData
	}
	originalPath = stateParts[1]
	if originalPath == "" {
		originalPath = "/"
	}
	return originalPath, nil
}
