package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantKey   string
		wantError error
	}{
		{
			name:      "valid api key",
			header:    "ApiKey 12345",
			wantKey:   "12345",
			wantError: nil,
		},
		{
			name:      "missing header",
			header:    "",
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "wrong scheme",
			header:    "Bearer 12345",
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name:      "no key provided",
			header:    "ApiKey",
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			gotKey, err := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("expected key %v, got %v", tt.wantKey, gotKey)
			}

			if tt.wantError != nil {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
