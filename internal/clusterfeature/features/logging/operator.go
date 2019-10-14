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
	"encoding/json"
	"fmt"

	"emperror.dev/errors"
	"github.com/banzaicloud/pipeline/auth"
	pkgCluster "github.com/banzaicloud/pipeline/cluster"
	"github.com/banzaicloud/pipeline/config"
	"github.com/banzaicloud/pipeline/internal/clusterfeature"
	"github.com/banzaicloud/pipeline/internal/clusterfeature/clusterfeatureadapter"
	"github.com/banzaicloud/pipeline/internal/clusterfeature/features"
	"github.com/banzaicloud/pipeline/internal/common"
	pkgSecret "github.com/banzaicloud/pipeline/pkg/secret"
	"github.com/banzaicloud/pipeline/secret"
)

// FeatureOperator implements the Logging feature operator
type FeatureOperator struct {
	clusterGetter  clusterfeatureadapter.ClusterGetter
	clusterService clusterfeature.ClusterService
	helmService    features.HelmService
	secretStore    features.SecretStore
	grafanaService features.GrafanaSecretService
	config         Configuration
	logger         common.Logger
}

// MakeFeatureOperator returns a Logging feature operator
func MakeFeatureOperator(
	clusterGetter clusterfeatureadapter.ClusterGetter,
	clusterService clusterfeature.ClusterService,
	helmService features.HelmService,
	secretStore features.SecretStore,
	config Configuration,
	logger common.Logger,
) FeatureOperator {
	grafanaService := features.NewGrafanaSecretService(config.grafanaAdminUsername, secretStore, logger)
	return FeatureOperator{
		clusterGetter:  clusterGetter,
		clusterService: clusterService,
		helmService:    helmService,
		secretStore:    secretStore,
		grafanaService: grafanaService,
		config:         config,
		logger:         logger,
	}
}

// Name returns the name of the Logging feature
func (op FeatureOperator) Name() string {
	return featureName
}

// Apply applies the provided specification to the cluster feature
func (op FeatureOperator) Apply(ctx context.Context, clusterID uint, spec clusterfeature.FeatureSpec) error {
	if err := op.clusterService.CheckClusterReady(ctx, clusterID); err != nil {
		return err
	}

	ctx, err := op.ensureOrgIDInContext(ctx, clusterID)
	if err != nil {
		return err
	}

	logger := op.logger.WithContext(ctx).WithFields(map[string]interface{}{"cluster": clusterID, "feature": featureName})

	boundSpec, err := bindFeatureSpec(spec)
	if err != nil {
		return clusterfeature.InvalidFeatureSpecError{
			FeatureName: featureName,
			Problem:     err.Error(),
		}
	}

	cl, err := op.clusterGetter.GetClusterByIDOnly(ctx, clusterID)
	if err != nil {
		return errors.WrapIf(err, "failed to get cluster")
	}

	if boundSpec.Settings.Tls {
		// generate TLS secret
		if err := op.generateTLSSecret(ctx, cl); err != nil {
			return errors.WrapIf(err, "failed to generate TLS secret for logging feature")
		}

		// install TLS secret to cluster
		if err := op.installTLSSecretsToCluster(ctx, cl); err != nil {
			return errors.WrapIf(err, "failed to install TLS secret")
		}
	}

	// generate Grafana secret
	//grafanaSecretID, err := op.generateGrafanaSecret(ctx, cl, boundSpec)
	_, err = op.generateGrafanaSecret(ctx, cl, boundSpec)
	if err != nil {
		return errors.WrapIf(err, "failed to generate Grafana secret")
	}

	// install Loki
	if boundSpec.Loki.Enabled {
		if err := op.installLoki(ctx, clusterID); err != nil {
			return errors.WrapIf(err, "failed to install Loki")
		}
	}

	// install logging-operator
	if err := op.installLoggingOperator(ctx, clusterID, cl, logger); err != nil {
		return errors.WrapIf(err, fmt.Sprintf("failed to install deployment: %q", op.config.operator.chartName))
	}

	// install logging-operator-logging
	if err := op.installLoggingOperatorLogging(ctx, clusterID, boundSpec, logger); err != nil {
		return errors.WrapIf(err, fmt.Sprintf("failed to install deployment: %q", op.config.logging.chartName))
	}

	return nil
}

// Deactivate deactivates the cluster feature
func (op FeatureOperator) Deactivate(ctx context.Context, clusterID uint, spec clusterfeature.FeatureSpec) error {
	if err := op.clusterService.CheckClusterReady(ctx, clusterID); err != nil {
		return err
	}

	ctx, err := op.ensureOrgIDInContext(ctx, clusterID)
	if err != nil {
		return err
	}

	logger := op.logger.WithContext(ctx).WithFields(map[string]interface{}{"cluster": clusterID, "feature": featureName})

	// TODO (colin): remove Loki, warn, what if the user disable Loki and deactivate feature?

	// delete deployment
	if err := op.helmService.DeleteDeployment(ctx, clusterID, config.LoggingOperatorReleaseName); err != nil {
		logger.Info(fmt.Sprintf("failed to delete feature deployment: %q", config.LoggingOperatorReleaseName))

		return errors.WrapIf(err, fmt.Sprintf("failed to uninstall deployment: %q", config.LoggingOperatorReleaseName))
	}

	// remove TLS secret from Vault
	if err := op.deleteTLSSecret(ctx, clusterID); err != nil {
		return errors.WrapIf(err, "failed to delete TLS secret from Vault")
	}

	return nil
}

func (op FeatureOperator) installLoki(ctx context.Context, clusterID uint) error {
	chartName := op.config.loki.chartName
	chartVersion := op.config.loki.chartVersion

	return op.helmService.ApplyDeployment(
		ctx,
		clusterID,
		op.config.pipelineSystemNamespace,
		chartName,
		lokiReleaseName,
		[]byte{},
		chartVersion,
	)
}

func (op FeatureOperator) installLoggingOperator(ctx context.Context, clusterID uint, cluster clusterfeatureadapter.Cluster, logger common.Logger) error {

	var tolerationService = features.NewTolerationService(op.config.headNodepoolName)
	var affinityService = features.NewAffinityService(op.config.headNodepoolName, cluster)
	headNodeAffinity := affinityService.GetHeadNodeAffinity()
	tolerations := tolerationService.GetHeadNodeTolerations()

	var chartValues = loggingOperatorValues{
		Affinity:    headNodeAffinity,
		Tolerations: tolerations,
	}

	valuesBytes, err := json.Marshal(chartValues)
	if err != nil {
		logger.Debug("failed to marshal chartValues")
		return errors.WrapIf(err, "failed to decode chartValues")
	}

	return op.helmService.ApplyDeployment(
		ctx,
		clusterID,
		op.config.pipelineSystemNamespace,
		op.config.operator.chartName,
		config.LoggingOperatorReleaseName,
		valuesBytes,
		op.config.operator.chartVersion,
	)
}

func (op FeatureOperator) installLoggingOperatorLogging(ctx context.Context, clusterID uint, spec loggingFeatureSpec, logger common.Logger) error {
	var chartValues = loggingOperatorLoggingValues{
		// todo (colin): extend me
		Tls: tlsValues{
			Enabled:             spec.Settings.Tls,
			FluentdSecretName:   fluentdSecretName,
			FluentbitSecretName: fluentbitSecretName,
		},
	}

	valuesBytes, err := json.Marshal(chartValues)
	if err != nil {
		logger.Debug("failed to marshal chartValues")
		return errors.WrapIf(err, "failed to decode chartValues")
	}

	return op.helmService.ApplyDeployment(
		ctx,
		clusterID,
		op.config.pipelineSystemNamespace,
		op.config.logging.chartName,
		config.LoggingReleaseName,
		valuesBytes,
		op.config.logging.chartVersion,
	)
}

func (op FeatureOperator) generateTLSSecret(ctx context.Context, cluster clusterfeatureadapter.Cluster) error {
	var namespace = op.config.pipelineSystemNamespace
	var tlsHost = "fluentd." + namespace + ".svc.cluster.local"
	var secretName = getTLSSecretName(cluster.GetID())

	// check secret exists
	existingSecretID, err := op.secretStore.GetIDByName(ctx, secretName)
	if existingSecretID != "" {
		op.logger.Debug("TLS secret already exists")
		return nil
	} else if isSecretNotFoundError(err) {
		req := &secret.CreateSecretRequest{
			Name: secretName,
			Type: pkgSecret.TLSSecretType,
			Tags: []string{
				pkgSecret.TagBanzaiReadonly,
				secretTag,
			},
			Values: map[string]string{
				pkgSecret.TLSHosts: tlsHost,
			},
		}

		// store TLS secret
		_, err := op.secretStore.Store(ctx, req)
		if err != nil {
			return errors.WrapIf(err, "failed generate TLS secrets to logging operator")
		}
	} else {
		return errors.WrapIf(err, "error during getting TLS secret")
	}

	return nil
}

func (op FeatureOperator) installTLSSecretsToCluster(ctx context.Context, cl clusterfeatureadapter.Cluster) error {

	var namespace = op.config.pipelineSystemNamespace
	var secretName = getTLSSecretName(cl.GetID())

	_, err := pkgCluster.InstallSecret(cl, fluentbitSecretName, pkgCluster.InstallSecretRequest{
		SourceSecretName: secretName,
		Namespace:        namespace,
		Update:           true,
		Spec: map[string]pkgCluster.InstallSecretRequestSpecItem{
			kubeCaCertKey:  {Source: pkgSecret.CACert},
			kubeTlsCertKey: {Source: pkgSecret.ClientCert},
			kubeTlsKeyKey:  {Source: pkgSecret.ClientKey},
		},
	})
	if err != nil {
		return errors.WrapIfWithDetails(err, "failed to install fluentbit secret to the cluster", "clusterID", cl.GetID())
	}

	_, err = pkgCluster.InstallSecret(cl, fluentdSecretName, pkgCluster.InstallSecretRequest{
		SourceSecretName: secretName,
		Namespace:        namespace,
		Update:           true,
		Spec: map[string]pkgCluster.InstallSecretRequestSpecItem{
			kubeCaCertKey:  {Source: pkgSecret.CACert},
			kubeTlsCertKey: {Source: pkgSecret.ServerCert},
			kubeTlsKeyKey:  {Source: pkgSecret.ServerKey},
		},
	})
	if err != nil {
		return errors.WrapIfWithDetails(err, "failed to install fluentd secret to the cluster", "clusterID", cl.GetID())
	}

	return nil
}

func (op FeatureOperator) deleteTLSSecret(ctx context.Context, clusterID uint) error {
	var secretName = getTLSSecretName(clusterID)
	secretID, err := op.secretStore.GetIDByName(ctx, secretName)
	if err != nil && !isSecretNotFoundError(err) {
		return errors.WrapIf(err, "failed to get TLS secret")
	}

	if err := op.secretStore.Delete(ctx, secretID); err != nil {
		return errors.WrapIf(err, "failed to delete TLS secret")
	}

	return nil
}

func (op FeatureOperator) ensureOrgIDInContext(ctx context.Context, clusterID uint) (context.Context, error) {
	if _, ok := auth.GetCurrentOrganizationID(ctx); !ok {
		cluster, err := op.clusterGetter.GetClusterByIDOnly(ctx, clusterID)
		if err != nil {
			return ctx, errors.WrapIf(err, "failed to get cluster by ID")
		}
		ctx = auth.SetCurrentOrganizationID(ctx, cluster.GetOrganizationId())
	}
	return ctx, nil
}

func (op FeatureOperator) generateGrafanaSecret(ctx context.Context, cluster clusterfeatureadapter.Cluster, boundSpec loggingFeatureSpec) (string, error) {
	var clusterID = cluster.GetID()
	var orgID = cluster.GetOrganizationId()

	releaseSecretTag := getReleaseSecretTag()

	var grafanaSecretID = boundSpec.Grafana.SecretId
	var err error
	if boundSpec.Grafana.Enabled && grafanaSecretID == "" {
		grafanaSecretID, err = op.grafanaService.GenerateSecret(
			ctx,
			clusterID,
			orgID,
			append(getSecretClusterTags(cluster), releaseSecretTag),
		)
	}

	return grafanaSecretID, err
}
