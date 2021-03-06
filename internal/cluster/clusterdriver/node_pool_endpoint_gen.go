// Code generated by mga tool. DO NOT EDIT.
package clusterdriver

import (
	"github.com/banzaicloud/pipeline/internal/cluster"
	"github.com/go-kit/kit/endpoint"
	kitoc "github.com/go-kit/kit/tracing/opencensus"
	kitxendpoint "github.com/sagikazarmark/kitx/endpoint"
)

// NodePoolEndpoints collects all of the endpoints that compose the underlying service. It's
// meant to be used as a helper struct, to collect all of the endpoints into a
// single parameter.
type NodePoolEndpoints struct {
	DeleteNodePool endpoint.Endpoint
}

// MakeNodePoolEndpoints returns a(n) NodePoolEndpoints struct where each endpoint invokes
// the corresponding method on the provided service.
func MakeNodePoolEndpoints(service cluster.NodePoolService, middleware ...endpoint.Middleware) NodePoolEndpoints {
	mw := kitxendpoint.Chain(middleware...)

	return NodePoolEndpoints{DeleteNodePool: mw(MakeDeleteNodePoolEndpoint(service))}
}

// TraceNodePoolEndpoints returns a(n) NodePoolEndpoints struct where each endpoint is wrapped with a tracing middleware.
func TraceNodePoolEndpoints(endpoints NodePoolEndpoints) NodePoolEndpoints {
	return NodePoolEndpoints{DeleteNodePool: kitoc.TraceEndpoint("cluster.DeleteNodePool")(endpoints.DeleteNodePool)}
}
