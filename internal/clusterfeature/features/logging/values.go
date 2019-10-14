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

type loggingOperatorValues struct {
	Affinity    interface{} `json:"affinity" mapstructure:"affinity"`
	Tolerations interface{} `json:"tolerations" mapstructure:"tolerations"`
}

type loggingOperatorLoggingValues struct {
	Tls tlsValues `json:"tls" mapstructure:"tls"`
}

type tlsValues struct {
	Enabled             bool   `json:"enabled" mapstructure:"enabled"`
	FluentdSecretName   string `json:"fluentdSecretName" mapstructure:"fluentdSecretName"`
	FluentbitSecretName string `json:"fluentbitSecretName" mapstructure:"fluentbitSecretName"`
}

type grafanaValues struct {
	Ingress       ingressValues    `json:"ingress"`
	AdminUser     string           `json:"adminUser"`
	AdminPassword string           `json:"adminPassword"`
	GrafanaIni    grafanaIniValues `json:"grafana.ini"`
	Affinity      interface{}      `json:"affinity"`
	Tolerations   interface{}      `json:"tolerations"`
}

type ingressValues struct {
	Enabled bool     `json:"enabled"`
	Hosts   []string `json:"hosts"`
	Path    string   `json:"path,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

type grafanaIniValues struct {
	Server grafanaIniServerValues `json:"server"`
}

type grafanaIniServerValues struct {
	RootUrl          string `json:"root_url"`
	ServeFromSubPath bool   `json:"serve_from_sub_path"`
}
