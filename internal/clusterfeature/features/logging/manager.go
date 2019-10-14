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
	"context"

	"emperror.dev/errors"
	"github.com/banzaicloud/pipeline/internal/clusterfeature"
	"github.com/banzaicloud/pipeline/internal/clusterfeature/clusterfeatureadapter"
	"github.com/banzaicloud/pipeline/internal/clusterfeature/features"
	"github.com/banzaicloud/pipeline/internal/common"
)

type FeatureManager struct {
	clusterGetter  clusterfeatureadapter.ClusterGetter
	config         Configuration
	secretStore    features.SecretStore
	grafanaService features.GrafanaSecretService
	helmService    features.HelmService
	logger         common.Logger
}

// NewVaultFeatureManager builds a new feature manager component
func MakeFeatureManager(
	clusterGetter clusterfeatureadapter.ClusterGetter,
	config Configuration,
	secretStore features.SecretStore,
	helmService features.HelmService,
	logger common.Logger,
) FeatureManager {
	grafanaService := features.NewGrafanaSecretService(config.grafanaAdminUsername, secretStore, logger)
	return FeatureManager{
		clusterGetter:  clusterGetter,
		config:         config,
		secretStore:    secretStore,
		grafanaService: grafanaService,
		helmService:    helmService,
		logger:         logger,
	}
}

func (FeatureManager) Name() string {
	return featureName
}

func (m FeatureManager) GetOutput(ctx context.Context, clusterID uint, spec clusterfeature.FeatureSpec) (clusterfeature.FeatureOutput, error) {
	// TODO (colin): extends me

	boundSpec, err := bindFeatureSpec(spec)
	if err != nil {
		return nil, err
	}

	tlsOutput, err := m.getTLSOutput(ctx, clusterID, boundSpec.Settings.Tls)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get TLS output")
	}

	grafanaOutput, err := m.getGrafanaOutput(ctx, boundSpec.Grafana, clusterID)
	if err != nil {
		return nil, errors.WrapIf(err, "failed to get Grafana output")
	}

	lokiOutput, err := m.getLokiOutput(ctx, boundSpec.Loki, clusterID)
	if err != nil {
		// todo (colin): need error???
		return nil, errors.WrapIf(err, "failed to get Loki output")
	}

	var output = clusterfeature.FeatureOutput{
		"loggingOperator": obj{
			"version": m.config.operator.chartVersion,
		},
		"logging": obj{
			"version": m.config.logging.chartVersion,
		},
		"tls":     tlsOutput,
		"grafana": grafanaOutput,
		"loki":    lokiOutput,
	}
	return output, nil
}

func (m FeatureManager) ValidateSpec(ctx context.Context, spec clusterfeature.FeatureSpec) error {
	vaultSpec, err := bindFeatureSpec(spec)
	if err != nil {
		return err
	}

	if err := vaultSpec.Validate(); err != nil {
		return clusterfeature.InvalidFeatureSpecError{
			FeatureName: featureName,
			Problem:     err.Error(),
		}
	}

	return nil
}

func (m FeatureManager) PrepareSpec(ctx context.Context, spec clusterfeature.FeatureSpec) (clusterfeature.FeatureSpec, error) {
	return spec, nil
}

func (m FeatureManager) getGrafanaOutput(ctx context.Context, spec baseComponentSpec, clusterID uint) (obj, error) {
	if spec.Enabled {
		var grafanaSecretID = spec.SecretId
		var err error
		if grafanaSecretID == "" {
			var secretName = m.grafanaService.GetGrafanaSecretName(clusterID)
			grafanaSecretID, err = m.secretStore.GetIDByName(ctx, secretName)
			if err != nil {
				return nil, errors.WrapIf(err, "failed to get Grafana secret")
			}
		}

		// todo (colin): get Grafana url and version
		return obj{
			"secretId": grafanaSecretID,
		}, nil
	}

	return nil, nil
}

func (m FeatureManager) getLokiOutput(ctx context.Context, lokiSpec baseComponentSpec, clusterID uint) (obj, error) {
	var output obj
	if lokiSpec.Enabled {
		lokiValues, err := m.helmService.GetDeployment(ctx, clusterID, lokiReleaseName)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to get loki deployment values")
		}

		if image, ok := lokiValues.Values["image"].(map[string]interface{}); ok {
			output = obj{
				"version": image["tag"],
			}
		}
	}

	return output, nil
}

func (m FeatureManager) getTLSOutput(ctx context.Context, clusterID uint, isEnabled bool) (obj, error) {
	if isEnabled {
		var tlsSecretName = getTLSSecretName(clusterID)
		tlsSecretID, err := m.secretStore.GetIDByName(ctx, tlsSecretName)
		if err != nil {
			return nil, errors.WrapIf(err, "failed to get TLS secret from Vault")
		}

		return obj{
			"secretId": tlsSecretID,
		}, nil
	}

	return nil, nil
}
