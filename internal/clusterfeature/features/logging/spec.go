// Copyright © 2019 Banzai Cloud
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

package logging

import (
	"fmt"

	"emperror.dev/errors"
	"github.com/banzaicloud/pipeline/dns"
	"github.com/banzaicloud/pipeline/internal/clusterfeature"
	"github.com/mitchellh/mapstructure"
)

type loggingFeatureSpec struct {
	Grafana       baseComponentSpec `json:"grafana" mapstructure:"grafana"`
	Loki          baseComponentSpec `json:"loki" mapstructure:"loki"`
	Settings      settingsSpec      `json:"settings" mapstructure:"settings"`
	ClusterOutput clusterOutputSpec `json:"clusterOutput" mapstructure:"clusterOutput"`
}

type baseComponentSpec struct {
	Enabled  bool   `json:"enabled" mapstructure:"enabled"`
	Domain   string `json:"domain" mapstructure:"domain"`
	Path     string `json:"path" mapstructure:"path"`
	SecretId string `json:"secretId" mapstructure:"secretId"`
}

type settingsSpec struct {
	Monitoring bool `json:"monitoring" mapstructure:"enabled"`
	Tls        bool `json:"tls" mapstructure:"tls"`
}

type clusterOutputSpec struct {
	Enabled  bool         `json:"enabled" mapstructure:"enabled"`
	Provider providerSpec `json:"provider" mapstructure:"provider"`
}

type providerSpec struct {
	Name     string `json:"name" mapstructure:"enabled"`
	Bucket   string `json:"bucket" mapstructure:"bucket"`
	SecretId string `json:"secretId" mapstructure:"secretId"`
}

func (s providerSpec) Validate() error {
	switch s.Name {
	case providerAmazonS3, providerGoogleGCS, providerAlibabaOSS, providerAzure:
	default:
		return invalidProviderError{provider: s.Name}
	}

	return nil
}

func (s baseComponentSpec) Validate(componentType string) error {
	if s.Enabled {

		if s.Path == "" {
			return requiredFieldError{fieldName: fmt.Sprintf("%s path", componentType)}
		}

		if s.Domain != "" {
			err := dns.ValidateSubdomain(s.Domain)
			if err != nil {
				return errors.Append(err, invalidDomainError{domain: s.Domain})
			}
		}
	}

	return nil
}

type invalidProviderError struct {
	provider string
}

func (e invalidProviderError) Error() string {
	return fmt.Sprintf("invalid provider: %q", e.provider)
}

type requiredFieldError struct {
	fieldName string
}

func (e requiredFieldError) Error() string {
	return fmt.Sprintf("%q cannot be empty", e.fieldName)
}

type invalidDomainError struct {
	domain string
}

func (e invalidDomainError) Error() string {
	return fmt.Sprintf("invalid domain: %q", e.domain)
}

func (s loggingFeatureSpec) Validate() error {
	if err := s.Grafana.Validate("Grafana"); err != nil {
		return err
	}

	if err := s.Loki.Validate("Loki"); err != nil {
		return err
	}

	if s.ClusterOutput.Enabled {
		if err := s.ClusterOutput.Provider.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func bindFeatureSpec(spec clusterfeature.FeatureSpec) (loggingFeatureSpec, error) {
	var featureSpec loggingFeatureSpec
	if err := mapstructure.Decode(spec, &featureSpec); err != nil {
		return featureSpec, clusterfeature.InvalidFeatureSpecError{
			FeatureName: featureName,
			Problem:     "failed to bind feature spec",
		}
	}

	return featureSpec, nil
}
