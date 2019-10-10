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
	v1 "k8s.io/api/core/v1"

	pkgCommon "github.com/banzaicloud/pipeline/pkg/common"
)

type TolerationService struct {
	headNodepoolName string
}

func NewTolerationService(headNodepoolName string) TolerationService {
	return TolerationService{
		headNodepoolName: headNodepoolName,
	}
}

func (s TolerationService) GetHeadNodeTolerations() []v1.Toleration {
	if s.headNodepoolName == "" {
		return []v1.Toleration{}
	}
	return []v1.Toleration{
		{
			Key:      pkgCommon.NodePoolNameTaintKey,
			Operator: v1.TolerationOpEqual,
			Value:    s.headNodepoolName,
		},
	}
}
