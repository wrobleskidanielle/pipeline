// Code generated by mockery v1.0.0. DO NOT EDIT.

package tokendriver

import context "context"
import mock "github.com/stretchr/testify/mock"

// MockAuthorizer is an autogenerated mock type for the Authorizer type
type MockAuthorizer struct {
	mock.Mock
}

// Authorize provides a mock function with given fields: ctx, action, object
func (_m *MockAuthorizer) Authorize(ctx context.Context, action string, object interface{}) (bool, error) {
	ret := _m.Called(ctx, action, object)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, string, interface{}) bool); ok {
		r0 = rf(ctx, action, object)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, interface{}) error); ok {
		r1 = rf(ctx, action, object)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
