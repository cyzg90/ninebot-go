package api

import "ninecli/internal/crypto"

// BusinessLogin exchanges Passport credentials for a business UID.
func (c *Client) BusinessLogin() (map[string]any, error) {
	if c.Tokens == nil || c.Tokens.AccessToken == "" {
		return nil, errNoTokens
	}

	// BusinessLogin requires Passport credentials.
	// Omit the business UID until the exchange succeeds.
	probe := *c
	tokens := *c.Tokens
	tokens.UID = ""
	tokens.BizUID = ""
	probe.Tokens = &tokens

	extras := []crypto.KV{
		{Key: "uuid", Value: c.Tokens.UID},
		{Key: "token", Value: c.Tokens.AccessToken},
		{Key: "refresh_token", Value: c.Tokens.RefreshToken},
		{Key: "region", Value: c.Cfg.Region},
	}

	m, _, err := probe.EncryptedPost(
		c.Hosts.BizHost+"/user/user/login",
		extras,
		map[string]string{
			"Business-Type": "0",
		},
	)
	if err != nil {
		return nil, err
	}
	return m, nil
}
