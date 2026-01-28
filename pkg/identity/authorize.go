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

package identity

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/log"
)

// We do this to bypass needing actual OIDC tokens for unit testing.
var Authorize = actualAuthorize

func actualAuthorize(ctx context.Context, token string, opts ...config.InsecureOIDCConfigOption) (*oidc.IDToken, error) {
	claims, err := extractTokenClaims(token)
	if err != nil {
		log.Logger.Debugf("actualAuthorize: failed to extract token claims: %v", err)
		return nil, err
	}

	log.Logger.Debugf("actualAuthorize: authorizing token with issuer=%q audience=%q", claims.Issuer, claims.Audience)

	verifier, ok := config.FromContext(ctx).GetVerifier(claims.Issuer, claims.Audience, opts...)
	if !ok {
		log.Logger.Warnf("actualAuthorize: no verifier found for issuer=%q audience=%q", claims.Issuer, claims.Audience)
		return nil, fmt.Errorf("unsupported issuer: %s", claims.Issuer)
	}

	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		log.Logger.Warnf("actualAuthorize: token verification failed for issuer=%q audience=%q: %v", claims.Issuer, claims.Audience, err)
		return nil, err
	}
	log.Logger.Debugf("actualAuthorize: token verified successfully for issuer=%q audience=%q subject=%q", claims.Issuer, claims.Audience, idToken.Subject)
	return idToken, nil
}
