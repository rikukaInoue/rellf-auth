package oidc

import (
	"crypto/subtle"
	"fmt"
	"strings"
)

// OIDCClient represents a registered OIDC client.
type OIDCClient struct {
	ClientID     string
	ClientSecret string // empty for public clients
	ClientType   string // "public" or "confidential"
	RedirectURIs []string
}

// IsPublic returns true if this is a public client (no secret).
func (c *OIDCClient) IsPublic() bool {
	return c.ClientType == "public"
}

// ClientRegistry manages registered OIDC clients.
type ClientRegistry struct {
	clients map[string]*OIDCClient
}

// NewClientRegistry creates a registry from a list of clients.
func NewClientRegistry(clients []OIDCClient) *ClientRegistry {
	m := make(map[string]*OIDCClient, len(clients))
	for i := range clients {
		m[clients[i].ClientID] = &clients[i]
	}
	return &ClientRegistry{clients: m}
}

// ParseClients parses the OIDC_CLIENTS env var format:
// "client_id:secret:type:redirect_uri1|redirect_uri2,client_id2:secret2:type2:uri"
func ParseClients(raw string) ([]OIDCClient, error) {
	if raw == "" {
		return nil, fmt.Errorf("OIDC_CLIENTS is empty")
	}

	var clients []OIDCClient
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, ":", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid client entry %q: expected client_id:secret:type:redirect_uris", entry)
		}

		clientID := parts[0]
		secret := parts[1]
		clientType := parts[2]
		redirectURIs := strings.Split(parts[3], "|")

		if clientType != "public" && clientType != "confidential" {
			return nil, fmt.Errorf("invalid client type %q for client %q: must be 'public' or 'confidential'", clientType, clientID)
		}

		clients = append(clients, OIDCClient{
			ClientID:     clientID,
			ClientSecret: secret,
			ClientType:   clientType,
			RedirectURIs: redirectURIs,
		})
	}

	if len(clients) == 0 {
		return nil, fmt.Errorf("no clients parsed from OIDC_CLIENTS")
	}

	return clients, nil
}

// Validate checks that the client_id exists and the redirect_uri is registered.
func (r *ClientRegistry) Validate(clientID, redirectURI string) (*OIDCClient, error) {
	client, ok := r.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("unknown client_id: %s", clientID)
	}

	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return client, nil
		}
	}

	return nil, fmt.Errorf("redirect_uri %q not registered for client %s", redirectURI, clientID)
}

// ValidateSecret checks client_id and client_secret for confidential clients.
func (r *ClientRegistry) ValidateSecret(clientID, clientSecret string) (*OIDCClient, error) {
	client, ok := r.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("unknown client_id: %s", clientID)
	}

	if client.IsPublic() {
		return client, nil
	}

	if subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, fmt.Errorf("invalid client_secret for client %s", clientID)
	}

	return client, nil
}
