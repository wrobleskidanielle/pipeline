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

package clustersetup

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.uber.org/cadence/testsuite"
	"go.uber.org/cadence/workflow"
)

// nolint: gochecknoglobals
var testCluster = Cluster{
	ID:           1,
	UID:          "260e50ee-d817-4b62-85bd-3260f0e019a0",
	Name:         "example-cluster",
	Distribution: "pke",
}

// nolint: gochecknoglobals
var testOrganization = Organization{
	ID:   1,
	Name: "example-organization",
}

// nolint: gochecknoglobals
var testNodePoolLabels = map[string]map[string]string{
	"pool1": {
		"key": "value",
	},
}

type WorkflowTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func TestWorkflowTestSuite(t *testing.T) {
	suite.Run(t, new(WorkflowTestSuite))
}

func (s *WorkflowTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *WorkflowTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *WorkflowTestSuite) Test_Success() {
	wf := Workflow{}
	workflow.RegisterWithOptions(wf.Execute, workflow.RegisterOptions{Name: s.T().Name()})

	s.env.OnActivity(
		CreatePipelineNamespaceActivityName,
		mock.Anything,
		CreatePipelineNamespaceActivityInput{ConfigSecretID: "secret"},
	).Return(nil)

	s.env.OnActivity(
		LabelKubeSystemNamespaceActivityName,
		mock.Anything,
		LabelKubeSystemNamespaceActivityInput{ConfigSecretID: "secret"},
	).Return(nil)

	s.env.OnActivity(
		InstallTillerActivityName,
		mock.Anything,
		InstallTillerActivityInput{ConfigSecretID: "secret", Distribution: testCluster.Distribution},
	).Return(nil)

	s.env.OnActivity(
		InstallTillerWaitActivityName,
		mock.Anything,
		InstallTillerWaitActivityInput{ConfigSecretID: "secret"},
	).Return(nil)

	s.env.OnActivity(
		InstallNodePoolLabelSetOperatorActivityName,
		mock.Anything,
		InstallNodePoolLabelSetOperatorActivityInput{ClusterID: 1},
	).Return(nil)

	s.env.OnActivity(
		ConfigureNodePoolLabelsActivityName,
		mock.Anything,
		ConfigureNodePoolLabelsActivityInput{
			ConfigSecretID: "secret",
			Labels:         testNodePoolLabels,
		},
	).Return(nil)

	workflowInput := WorkflowInput{
		ConfigSecretID: "secret",
		Cluster:        testCluster,
		Organization:   testOrganization,
		NodePoolLabels: testNodePoolLabels,
	}

	s.env.ExecuteWorkflow(s.T().Name(), workflowInput)

	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *WorkflowTestSuite) Test_Success_InstallInitManifest() {
	wf := Workflow{
		InstallInitManifest: true,
	}
	workflow.RegisterWithOptions(wf.Execute, workflow.RegisterOptions{Name: s.T().Name()})

	s.env.OnActivity(
		InitManifestActivityName,
		mock.Anything,
		InitManifestActivityInput{ConfigSecretID: "secret", Cluster: testCluster, Organization: testOrganization},
	).Return(nil)

	s.env.OnActivity(
		CreatePipelineNamespaceActivityName,
		mock.Anything,
		CreatePipelineNamespaceActivityInput{ConfigSecretID: "secret"},
	).Return(nil)

	s.env.OnActivity(
		LabelKubeSystemNamespaceActivityName,
		mock.Anything,
		LabelKubeSystemNamespaceActivityInput{ConfigSecretID: "secret"},
	).Return(nil)

	s.env.OnActivity(
		InstallTillerActivityName,
		mock.Anything,
		InstallTillerActivityInput{ConfigSecretID: "secret", Distribution: testCluster.Distribution},
	).Return(nil)

	s.env.OnActivity(
		InstallTillerWaitActivityName,
		mock.Anything,
		InstallTillerWaitActivityInput{ConfigSecretID: "secret"},
	).Return(nil)

	s.env.OnActivity(
		InstallNodePoolLabelSetOperatorActivityName,
		mock.Anything,
		InstallNodePoolLabelSetOperatorActivityInput{ClusterID: 1},
	).Return(nil)

	s.env.OnActivity(
		ConfigureNodePoolLabelsActivityName,
		mock.Anything,
		ConfigureNodePoolLabelsActivityInput{
			ConfigSecretID: "secret",
			Labels:         testNodePoolLabels,
		},
	).Return(nil)

	workflowInput := WorkflowInput{
		ConfigSecretID: "secret",
		Cluster:        testCluster,
		Organization:   testOrganization,
		NodePoolLabels: testNodePoolLabels,
	}

	s.env.ExecuteWorkflow(s.T().Name(), workflowInput)

	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}
