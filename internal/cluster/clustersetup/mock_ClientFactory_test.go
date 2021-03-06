// Code generated by mockery v1.0.0. DO NOT EDIT.

package clustersetup

import context "context"
import kubernetes "k8s.io/client-go/kubernetes"
import mock "github.com/stretchr/testify/mock"

// MockClientFactory is an autogenerated mock type for the ClientFactory type
type MockClientFactory struct {
	mock.Mock
}

// FromSecret provides a mock function with given fields: ctx, secretID
func (_m *MockClientFactory) FromSecret(ctx context.Context, secretID string) (kubernetes.Interface, error) {
	ret := _m.Called(ctx, secretID)

	var r0 kubernetes.Interface
	if rf, ok := ret.Get(0).(func(context.Context, string) kubernetes.Interface); ok {
		r0 = rf(ctx, secretID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(kubernetes.Interface)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, secretID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
