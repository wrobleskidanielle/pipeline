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

package issuedriver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-kit/kit/endpoint"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/banzaicloud/pipeline/internal/app/frontend/issue"
)

func TestRegisterHTTPHandlers_ReportIssue(t *testing.T) {
	handler := mux.NewRouter()
	RegisterHTTPHandlers(
		Endpoints{
			ReportIssue: endpoint.Nop,
		},
		handler.PathPrefix("/issues").Subrouter(),
	)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	newIssue := issue.NewIssue{
		OrganizationName: "example",
		Title:            "Something went wrong",
		Text:             "Here is my detailed issue",
		Labels:           []string{"bug"},
	}

	body, err := json.Marshal(newIssue)
	require.NoError(t, err)

	resp, err := ts.Client().Post(ts.URL+"/issues", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}
