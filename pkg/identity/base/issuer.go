// Copyright 2023 The Sigstore Authors.
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

package base

import (
	"context"
	"fmt"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
)

var (
	// For testing
	CmpOptions = cmpopts.IgnoreUnexported(baseIssuer{})
)

type baseIssuer struct {
	issuerURL string
	clientID  string
}

func Issuer(issuerURL, clientID string) identity.Issuer {
	return &baseIssuer{issuerURL: issuerURL, clientID: clientID}
}

// This is unimplemented for the base issuer, and should be implemented unique to each issuer
func (e *baseIssuer) Authenticate(ctx context.Context, token string, opts ...config.InsecureOIDCConfigOption) (identity.Principal, error) { //nolint: revive
	return nil, fmt.Errorf("unimplemented")
}

// Match is the same across issuers, so it doesn't need to be implemented anywhere else.
// It checks if the issuer URL matches and, when a clientID is configured, also checks
// that the token's audience matches the expected clientID.
func (e *baseIssuer) Match(_ context.Context, url string, audience string) bool {
	urlMatch := false
	if url == e.issuerURL {
		urlMatch = true
	} else {
		// If this is a MetaIssuer the issuer URL could be a regex
		// Check if the regex is valid against the provided url
		re, err := config.MetaRegex(e.issuerURL)
		if err != nil {
			return false
		}
		urlMatch = re.MatchString(url)
	}
	if !urlMatch {
		return false
	}
	// If a clientID is configured, also require the audience to match
	if e.clientID != "" {
		return audience == e.clientID
	}
	return true
}
