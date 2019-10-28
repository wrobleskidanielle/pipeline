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

package pke

import (
	"fmt"

	intCluster "github.com/banzaicloud/pipeline/internal/cluster"
	intPKE "github.com/banzaicloud/pipeline/internal/pke"
)

const PKEOnVSphere = "pke-on-vsphere"

type NodePool struct {
	Count uint
	VCPU  uint
	RamMB uint
	Max   uint
	Name  string
	Roles []string
}

type PKEOnVSphereCluster struct {
	intCluster.ClusterBase

	NodePools        []NodePool
	ResourceGroup    string
	Kubernetes       intPKE.Kubernetes
	ActiveWorkflowID string

	Monitoring   bool
	Logging      bool
	SecurityScan bool
	TtlMinutes   uint
}

func (c PKEOnVSphereCluster) HasActiveWorkflow() bool {
	return c.ActiveWorkflowID != ""
}

func GetVMName(clusterName, nodePoolName string, number int) string {
	return fmt.Sprintf("%s-%s-%02d", clusterName, nodePoolName, number)
}
