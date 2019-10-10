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

package features

import (
	"context"
	"fmt"

	"emperror.dev/errors"
	"github.com/banzaicloud/pipeline/secret"

	"github.com/banzaicloud/pipeline/internal/common"
	pkgSecret "github.com/banzaicloud/pipeline/pkg/secret"
)

const grafanaSecretTag = "app:grafana"

type GrafanaSecretService struct {
	username    string
	secretStore SecretStore
	logger      common.Logger
}

func NewGrafanaSecretService(username string, secretStore SecretStore, logger common.Logger) GrafanaSecretService {
	return GrafanaSecretService{
		username:    username,
		secretStore: secretStore,
		logger:      logger,
	}
}

func (s GrafanaSecretService) GenerateSecret(ctx context.Context, clusterID, orgID uint, tags []string) (string, error) {
	// Generating Grafana credentials
	password, err := secret.RandomString("randAlphaNum", 12)
	if err != nil {
		return "", errors.WrapIf(err, "failed to generate Grafana admin user password")
	}

	grafanaSecretRequest := secret.CreateSecretRequest{
		Name: s.GetGrafanaSecretName(clusterID),
		Type: pkgSecret.PasswordSecretType,
		Values: map[string]string{
			pkgSecret.Username: s.username,
			pkgSecret.Password: password,
		},
		Tags: append(tags, pkgSecret.TagBanzaiReadonly, grafanaSecretTag),
	}
	grafanaSecretID, err := s.secretStore.Store(ctx, &grafanaSecretRequest)
	if err != nil {
		return "", errors.WrapIf(err, "failed to store Grafana secret")
	}
	s.logger.Debug("Grafana secret stored")

	return grafanaSecretID, nil
}

func (s GrafanaSecretService) GetGrafanaSecretName(clusterID uint) string {
	return fmt.Sprintf("cluster-%d-grafana", clusterID)
}
