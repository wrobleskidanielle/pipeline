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
	"github.com/banzaicloud/pipeline/config"
	"github.com/spf13/viper"
)

type Configuration struct {
	pipelineSystemNamespace string
	operator                struct {
		chartName    string
		chartVersion string
	}
	logging struct {
		chartName    string
		chartVersion string
	}
	loki struct {
		chartName    string
		chartVersion string
	}
	grafanaAdminUsername string
	headNodepoolName     string
}

func NewConfig() Configuration {
	return Configuration{
		pipelineSystemNamespace: viper.GetString(config.PipelineSystemNamespace),
		operator: struct {
			chartName    string
			chartVersion string
		}{
			chartName:    viper.GetString(config.LoggingOperatorChartKey),
			chartVersion: viper.GetString(config.LoggingOperatorChartVersionKey),
		},
		logging: struct {
			chartName    string
			chartVersion string
		}{
			chartName:    viper.GetString(config.LoggingChartKey),
			chartVersion: viper.GetString(config.LoggingChartVersionKey),
		},
		loki: struct {
			chartName    string
			chartVersion string
		}{
			chartName:    viper.GetString(config.LoggingLokiChartKey),
			chartVersion: viper.GetString(config.LoggingLokiChartVersionKey),
		},
		grafanaAdminUsername: viper.GetString(config.MonitorGrafanaAdminUserNameKey),
		headNodepoolName:     viper.GetString(config.PipelineHeadNodePoolName),
	}
}
