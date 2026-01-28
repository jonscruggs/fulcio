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

package server

import (
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/identity"
	"github.com/sigstore/fulcio/pkg/identity/buildkite"
	"github.com/sigstore/fulcio/pkg/identity/chainguard"
	"github.com/sigstore/fulcio/pkg/identity/ciprovider"
	"github.com/sigstore/fulcio/pkg/identity/codefresh"
	"github.com/sigstore/fulcio/pkg/identity/email"
	"github.com/sigstore/fulcio/pkg/identity/github"
	"github.com/sigstore/fulcio/pkg/identity/gitlabcom"
	"github.com/sigstore/fulcio/pkg/identity/kubernetes"
	"github.com/sigstore/fulcio/pkg/identity/spiffe"
	"github.com/sigstore/fulcio/pkg/identity/uri"
	"github.com/sigstore/fulcio/pkg/identity/username"
	"github.com/sigstore/fulcio/pkg/log"
)

func NewIssuerPool(cfg *config.FulcioConfig) identity.IssuerPool {
	var ip identity.IssuerPool
	for key, i := range cfg.OIDCIssuers {
		log.Logger.Debugf("NewIssuerPool: adding OIDCIssuer key=%q issuerURL=%q type=%q clientID=%q", key, i.IssuerURL, i.Type, i.ClientID)
		iss := getIssuer("", i)
		if iss != nil {
			ip = append(ip, iss)
		} else {
			log.Logger.Warnf("NewIssuerPool: no issuer handler for type=%q key=%q", i.Type, key)
		}
	}
	for meta, i := range cfg.MetaIssuers {
		log.Logger.Debugf("NewIssuerPool: adding MetaIssuer pattern=%q type=%q clientID=%q", meta, i.Type, i.ClientID)
		iss := getIssuer(meta, i)
		if iss != nil {
			ip = append(ip, iss)
		} else {
			log.Logger.Warnf("NewIssuerPool: no issuer handler for type=%q meta=%q", i.Type, meta)
		}
	}
	log.Logger.Debugf("NewIssuerPool: created pool with %d issuers", len(ip))

	return ip
}

func getIssuer(meta string, i config.OIDCIssuer) identity.Issuer {
	issuerURL := i.IssuerURL
	if meta != "" {
		issuerURL = meta
	}
	switch i.Type {
	case config.IssuerTypeEmail:
		return email.Issuer(issuerURL)
	case config.IssuerTypeGithubWorkflow:
		return github.Issuer(issuerURL) // nolint
	case config.IssuerTypeCIProvider:
		return ciprovider.Issuer(issuerURL)
	case config.IssuerTypeGitLabPipeline:
		return gitlabcom.Issuer(issuerURL) // nolint
	case config.IssuerTypeBuildkiteJob:
		return buildkite.Issuer(issuerURL) // nolint
	case config.IssuerTypeCodefreshWorkflow:
		return codefresh.Issuer(issuerURL) // nolint
	case config.IssuerTypeChainguard:
		return chainguard.Issuer(issuerURL)
	case config.IssuerTypeKubernetes:
		return kubernetes.Issuer(issuerURL)
	case config.IssuerTypeSpiffe:
		return spiffe.Issuer(issuerURL)
	case config.IssuerTypeURI:
		return uri.Issuer(issuerURL)
	case config.IssuerTypeUsername:
		return username.Issuer(issuerURL)
	}
	return nil
}
