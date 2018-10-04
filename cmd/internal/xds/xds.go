package xds

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	"github.com/envoyproxy/go-control-plane/pkg/cache"
	"github.com/envoyproxy/go-control-plane/pkg/server"
	"github.com/envoyproxy/go-control-plane/pkg/test"
	"github.com/envoyproxy/go-control-plane/pkg/test/resource"
	"github.com/gogo/protobuf/types"
	"github.com/heroku/heroku-buildpack-envoy-proxy/cmd/internal/heroku"
)

const (
	// from go-control-plane/pkg/test
	mode = "xds"

	// from contour
	router     = "envoy.router"
	grpcWeb    = "envoy.grpc_web"
	httpFilter = "envoy.http_connection_manager"
)

func makeRoutes(events map[string]heroku.AppEvent) []cache.Resource {
	var resources []cache.Resource

	for _, ev := range events {
		resources = append(resources, &v2.RouteConfiguration{
			Name: ev.ID,
			VirtualHosts: []route.VirtualHost{{
				Name:    ev.ID,
				Domains: ev.Hostnames,
				Routes: []route.Route{
					{
						Match: route.RouteMatch{
							PathSpecifier: &route.RouteMatch_Prefix{
								Prefix: "/.well-known/",
							},
						},
						Action: &route.Route_Route{
							Route: &route.RouteAction{
								ClusterSpecifier: &route.RouteAction_Cluster{
									Cluster: "well_known_service",
								},
							},
						},
					},
					{
						Match: route.RouteMatch{
							PathSpecifier: &route.RouteMatch_Prefix{
								Prefix: "/",
							},
						},
						Action: &route.Route_Route{
							Route: &route.RouteAction{
								ClusterSpecifier: &route.RouteAction_Cluster{
									Cluster: "local_service",
								},
							},
						},
					},
				},
			}},
		})
	}

	return resources
}

func makeListener(events map[string]heroku.AppEvent) []cache.Resource {
	var resources []cache.Resource

	for _, ev := range events {
		l := v2.Listener{
			Name:    ev.ID,
			Address: socketaddress("0.0.0.0", 5000), // TODO: should be 12factord from HEROKU_ROUTER_HTTPS_PORT
		}

		filters := []listener.Filter{
			httpfilter(ev.ID, "TODO"),
		}

		fc := listener.FilterChain{
			TlsContext:    tlscontext(ev.Cert, ev.Key), // TODO: alpn, "h2", "http/1.1"),
			Filters:       filters,
			UseProxyProto: &types.BoolValue{Value: true},
		}

		l.FilterChains = append(l.FilterChains, fc)
		resources = append(resources, &l)
	}

	return resources
}

func httpfilter(routename, accessLogPath string) listener.Filter {
	return listener.Filter{
		Name: httpFilter,
		Config: &types.Struct{
			Fields: map[string]*types.Value{
				"stat_prefix": sv(routename),
				"rds": st(map[string]*types.Value{
					"route_config_name": sv(routename),
					"config_source": st(map[string]*types.Value{
						"api_config_source": st(map[string]*types.Value{
							"api_type": sv("GRPC"),
							"grpc_services": lv(
								st(map[string]*types.Value{
									"envoy_grpc": st(map[string]*types.Value{
										"cluster_name": sv("xds_cluster"),
									}),
								}),
							),
						}),
					}),
				}),
				"http_filters": lv(
					st(map[string]*types.Value{
						"name": sv(grpcWeb),
					}),
					st(map[string]*types.Value{
						"name": sv(router),
					}),
				),
				// "use_remote_address": bv(true), // TODO(jbeda) should this ever be false?
				// "access_log":         accesslog(accessLogPath),
			},
		},
	}
}

func socketaddress(address string, port uint32) core.Address {
	return core.Address{
		Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Protocol: core.TCP,
				Address:  address,
				PortSpecifier: &core.SocketAddress_PortValue{
					PortValue: port,
				},
			},
		},
	}
}

// TODO: make this loop and re-read on error
func (s *Server) populate(config cache.SnapshotCache) {
	resp, err := http.Get(s.FeedURL)
	if err != nil {
		log.Printf("err fetching feed URL: %s", err)
	}
	defer resp.Body.Close()

	f := heroku.Feed{AppID: s.AppID, Reader: resp.Body}
	ch := f.Start()

	i := 1
	for events := range ch {
		version := fmt.Sprintf("v%d", i)

		snapshot := cache.NewSnapshot(version, nil, nil,
			makeRoutes(events),
			makeListener(events),
		)

		if err := snapshot.Consistent(); err != nil {
			log.Printf("snapshot inconsistency: %+v err=%s", snapshot, err)
		}

		err := config.SetSnapshot(s.NodeID, snapshot)
		if err != nil {
			log.Printf("snapshot error %q for %+v", err, snapshot)
		}

		log.Printf("==> snapshot with version %s was set", version)

		i++
	}
}

type Server struct {
	NodeID        string
	Port          uint
	WellKnownPort uint
	AppID         string
	FeedURL       string
	Signal        chan struct{}
}

func (s *Server) Run(ctx context.Context) error {
	config := cache.NewSnapshotCache(mode == resource.Ads, Hasher{}, logger{})
	cb := &callbacks{signal: s.Signal}
	srv := server.NewServer(config, cb)

	go s.populate(config)
	test.RunManagementServer(ctx, srv, s.Port)
	return nil // TODO: Make RunManagementServer return an error
}

// Hasher returns node ID as an ID
type Hasher struct {
}

// ID function
func (h Hasher) ID(node *core.Node) string {
	if node == nil {
		return "unknown"
	}
	return node.Id
}

type logger struct{}

func (logger logger) Infof(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}
func (logger logger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERRO] "+format, args...)
}

// from contour
// TODO: func tlscontext(cert, key []byte, tlsMinProtoVersion auth.TlsParameters_TlsProtocol, alpnprotos ...string) *auth.DownstreamTlsContext {
func tlscontext(cert, key string) *auth.DownstreamTlsContext {
	return &auth.DownstreamTlsContext{
		CommonTlsContext: &auth.CommonTlsContext{
			// TODO
			// TlsParams: &auth.TlsParameters{
			// 	TlsMinimumProtocolVersion: tlsMinProtoVersion,
			// },
			TlsCertificates: []*auth.TlsCertificate{{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineString{
						InlineString: cert,
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineString{
						InlineString: key,
					},
				},
			}},
			// TODO
			// AlpnProtocols: alpnprotos,
		},
	}
}

func sv(s string) *types.Value {
	return &types.Value{Kind: &types.Value_StringValue{StringValue: s}}
}

func bv(b bool) *types.Value {
	return &types.Value{Kind: &types.Value_BoolValue{BoolValue: b}}
}

func st(m map[string]*types.Value) *types.Value {
	return &types.Value{Kind: &types.Value_StructValue{StructValue: &types.Struct{Fields: m}}}
}
func lv(v ...*types.Value) *types.Value {
	return &types.Value{Kind: &types.Value_ListValue{ListValue: &types.ListValue{Values: v}}}
}

type callbacks struct {
	signal   chan struct{}
	fetches  int
	requests int
	mu       sync.Mutex
}

func (cb *callbacks) Report() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	log.Printf("server callbacks: fetches=%d requests=%d", cb.fetches, cb.requests)
}

func (cb *callbacks) OnStreamOpen(_ context.Context, id int64, typ string) error {
	log.Printf("stream %d open for %s", id, typ)
	return nil
}
func (cb *callbacks) OnStreamClosed(id int64) {
	log.Printf("stream %d closed", id)
}
func (cb *callbacks) OnStreamRequest(int64, *v2.DiscoveryRequest) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.requests++
	if cb.signal != nil {
		close(cb.signal)
		cb.signal = nil
	}
}
func (cb *callbacks) OnStreamResponse(int64, *v2.DiscoveryRequest, *v2.DiscoveryResponse) {}
func (cb *callbacks) OnFetchRequest(_ context.Context, req *v2.DiscoveryRequest) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.fetches++
	if cb.signal != nil {
		close(cb.signal)
		cb.signal = nil
	}
	return nil
}
func (cb *callbacks) OnFetchResponse(*v2.DiscoveryRequest, *v2.DiscoveryResponse) {}
