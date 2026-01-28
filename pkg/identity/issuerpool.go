// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/log"
)

type IssuerPool []Issuer

func (p IssuerPool) Authenticate(ctx context.Context, token string, opts ...config.InsecureOIDCConfigOption) (Principal, error) {
	claims, err := extractTokenClaims(token)
	if err != nil {
		log.Logger.Debugf("IssuerPool.Authenticate: failed to extract token claims: %v", err)
		return nil, err
	}

	log.Logger.Debugf("IssuerPool.Authenticate: looking for issuer match for issuer=%q audience=%q among %d providers", claims.Issuer, claims.Audience, len(p))
	for _, issuer := range p {
		if issuer.Match(ctx, claims.Issuer) {
			log.Logger.Debugf("IssuerPool.Authenticate: matched issuer=%q, authenticating", claims.Issuer)
			return issuer.Authenticate(ctx, token, opts...)
		}
	}
	log.Logger.Warnf("IssuerPool.Authenticate: no configured provider matched issuer=%q audience=%q", claims.Issuer, claims.Audience)
	return nil, fmt.Errorf("failed to match issuer URL %s from token with any configured providers", claims.Issuer)
}

type tokenClaims struct {
	Issuer   string          `json:"iss"`
	Audience string          `json:"-"`
	RawAud   json.RawMessage `json:"aud"`
}

func (tc *tokenClaims) parseAudience() {
	if tc.RawAud == nil {
		return
	}
	// Try string first (OIDC allows aud as a single string)
	var s string
	if err := json.Unmarshal(tc.RawAud, &s); err == nil {
		tc.Audience = s
		return
	}
	// Try array of strings
	var arr []string
	if err := json.Unmarshal(tc.RawAud, &arr); err == nil && len(arr) > 0 {
		tc.Audience = arr[0]
	}
}

func extractTokenClaims(token string) (*tokenClaims, error) {
	if strings.Count(token, ".") != 2 {
		log.Logger.Debugf("extractTokenClaims: malformed jwt, expected 3 parts but got %d", strings.Count(token, ".")+1)
		return nil, fmt.Errorf("oidc: malformed jwt, token must have 3 parts")
	}

	parts := strings.SplitN(token, ".", 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Logger.Debugf("extractTokenClaims: failed to base64-decode jwt payload: %v", err)
		return nil, fmt.Errorf("oidc: malformed jwt payload: %w", err)
	}

	var claims tokenClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		log.Logger.Debugf("extractTokenClaims: failed to unmarshal jwt claims: %v", err)
		return nil, fmt.Errorf("oidc: failed to unmarshal claims: %w", err)
	}
	claims.parseAudience()
	log.Logger.Debugf("extractTokenClaims: parsed issuer=%q audience=%q", claims.Issuer, claims.Audience)
	return &claims, nil
}
