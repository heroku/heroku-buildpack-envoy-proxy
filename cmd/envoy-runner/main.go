package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/heroku/heroku-buildpack-envoy-proxy/cmd/internal/xds"
	"golang.org/x/sync/errgroup"
)

const (
	nodeCluster     = "heroku-buildpack-envoy-proxy"
	feedReadTimeout = 5 * time.Second
	appPort         = 8080

	wellKnownPort   = 8081
	wellKnownPrefix = "/.well-known/"

	acmURL    = "https://va-acm.heroku.com/challenge"
	acmPrefix = "/.well-known/acme-challenge/"

	probedomPrefix = "/.well-known/probedom-probe/"

	xdsPort = 18000
)

var config = struct {
	PlaintextPort         string
	RouterHealthcheckPort string
	RouterFeedURL         string

	AppID string
	Dyno  string
}{
	PlaintextPort:         os.Getenv("HEROKU_ROUTER_HTTP_PORT"),
	RouterHealthcheckPort: os.Getenv("HEROKU_ROUTER_HEALTHCHECK_PORT"),
	RouterFeedURL:         os.Getenv("HEROKU_ROUTER_FEED_URL"),

	AppID: os.Getenv("APP_ID"),
	Dyno:  os.Getenv("DYNO"),
}

func main() {
	if config.RouterHealthcheckPort == "" {
		fmt.Fprintf(os.Stderr, "envoy-daemon only works with spaces-router-bypass\n")
		os.Exit(0)
	}

	file, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	err = configTemplate.Execute(file, struct {
		PlaintextPort   string
		AppPort         uint
		WellKnownPort   uint
		WellKnownPrefix string
		XDSPort         uint
		NodeID          string
		NodeCluster     string
	}{
		PlaintextPort:   config.PlaintextPort,
		AppPort:         appPort,
		WellKnownPort:   wellKnownPort,
		WellKnownPrefix: wellKnownPrefix,
		XDSPort:         xdsPort,
		NodeID:          config.Dyno,
		NodeCluster:     nodeCluster,
	})
	if err != nil {
		log.Fatal(err)
	}

	g := new(errgroup.Group)

	ready := make(chan struct{})

	g.Go(func() error {
		log.Println("<= waiting for initial xDS payload before ready health check...")
		<-ready
		srv := &tcpServer{port: config.RouterHealthcheckPort}
		return srv.run()
	})

	g.Go(func() error {
		server := &xds.Server{
			NodeID:        config.Dyno,
			Port:          18000,
			WellKnownPort: wellKnownPort,
			Signal:        ready,
			AppID:         config.AppID,
			FeedURL:       config.RouterFeedURL,
		}
		return server.Run(context.TODO())
	})

	g.Go(func() error {
		acmURL, err := url.Parse(acmURL)
		if err != nil {
			return err
		}

		http.HandleFunc(probedomPrefix, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		http.HandleFunc(acmPrefix, func(w http.ResponseWriter, r *http.Request) {
			qs := url.Values{}
			qs.Set("token", strings.TrimPrefix(r.URL.Path, acmPrefix))
			qs.Set("host", r.Host)

			u := *acmURL
			u.RawQuery = qs.Encode()
			http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
		})

		return http.ListenAndServe(fmt.Sprintf(":%d", wellKnownPort), nil)
	})

	g.Go(func() error {
		cmd := exec.Command("envoy", "-c", file.Name(), "--log-format", "[envoy] %v")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	})

	log.Fatal(g.Wait())
}

// tcpServer answers healthcheck requests from TCP routers, such as an ELB.
type tcpServer struct {
	port string
	ln   net.Listener
}

// Run listens on the configured port and responds to healthcheck requests
// from TCP routers, such as an ELB.
func (s *tcpServer) run() error {
	if err := s.start(); err != nil {
		return err
	}

	return s.serve()
}

// Stop shuts down the tcpServer if it was already started.
//
// Stop implements the kit.Server interface.
func (s *tcpServer) stop(error) {
	if s.ln != nil {
		s.ln.Close()
	}
}

func (s *tcpServer) start() error {
	log.Printf("[envoy-buildpack-envoy-proxy] healthcheck - at=bind port=%s", s.port)
	ln, err := net.Listen("tcp", fmt.Sprintf(":%s", s.port))
	if err != nil {
		return err
	}

	s.ln = ln
	return nil
}

func (s *tcpServer) serve() error {
	const retryDelay = 50 * time.Millisecond

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				log.Printf("[envoy-buildpack-envoy-proxy] healthcheck - at=accept err=%s retrying in %s", err, retryDelay)
				time.Sleep(retryDelay)
				continue
			}

			return err
		}

		go s.serveConn(conn)
	}
}

func (s *tcpServer) serveConn(conn net.Conn) {
	defer conn.Close()

	if _, err := conn.Write([]byte("OK\n")); err != nil {
		log.Printf("[envoy-buildpack-envoy-proxy] healthcheck - err=%s", err)
	}
}

var configTemplate = template.Must(template.New("config").Parse(`
{
  "node": {
    "cluster": "{{.NodeCluster}}",
    "id": "{{.NodeID}}"
  },
  "admin": {
    "access_log_path": "/dev/null",
    "address": {
      "socket_address": {
        "address": "127.0.0.1",
        "port_value": 9901
      }
    }
  },
  "dynamic_resources": {
    "cds_config": {
      "api_config_source": {
        "api_type": "GRPC",
        "grpc_services": [
          {
            "envoy_grpc": {
              "cluster_name": "xds_cluster"
            }
          }
        ]
      }
    },
    "lds_config": {
      "api_config_source": {
        "api_type": "GRPC",
        "grpc_services": [
          {
            "envoy_grpc": {
              "cluster_name": "xds_cluster"
            }
          }
        ]
      }
    }
  },
  "static_resources": {
    "listeners": [
      {
        "name": "plaintext_listener",
        "address": {
          "socket_address": {
            "address": "0.0.0.0",
            "port_value": {{.PlaintextPort}}
          }
        },
        "filter_chains": [
          {
            "filters": [
              {
                "name": "envoy.http_connection_manager",
                "config": {
                  "codec_type": "auto",
                  "stat_prefix": "ingress_http",
                  "route_config": {
                    "name": "local_route",
                    "virtual_hosts": [
                      {
                        "name": "backend",
                        "domains": ["*"],
                        "routes": [
                          {
                            "match": {
                              "prefix": "{{.WellKnownPrefix}}"
                            },
                            "route": {
                              "cluster": "well_known_service"
                            }
                          },
                          {
                            "match": {
                              "prefix": "/"
                            },
                            "route": {
                              "cluster": "local_service"
                            }
                          }
                        ]
                      }
                    ]
                  },
                  "http_filters": [
                    {
                      "name": "envoy.router",
                      "config": {}
                    }
                  ]
                }
              }
            ]
          }
        ]
      }
    ],

    "clusters": [
      {
        "name": "xds_cluster",
        "connect_timeout": "0.25s",
        "type": "STATIC",
        "lb_policy": "ROUND_ROBIN",
        "http2_protocol_options": {},
        "load_assignment": {
          "cluster_name": "xds_cluster",
          "endpoints": [
            {
              "lb_endpoints": [
                {
                  "endpoint": {
                    "address": {
                      "socket_address": {
                        "address": "127.0.0.1",
                        "port_value": {{.XDSPort}}
                      }
                    }
                  }
                }
              ]
            }
          ]
        }
      },
      {
        "name": "local_service",
        "connect_timeout": "0.25s",
        "type": "STRICT_DNS",
        "lb_policy": "ROUND_ROBIN",
        "hosts": [
          {
            "socket_address": {
              "address": "127.0.0.1",
              "port_value": {{.AppPort}}
            }
          }
        ]
      },
      {
        "name": "well_known_service",
        "connect_timeout": "0.25s",
        "type": "STRICT_DNS",
        "lb_policy": "ROUND_ROBIN",
        "hosts": [
          {
            "socket_address": {
              "address": "127.0.0.1",
              "port_value": {{.WellKnownPort}}
            }
          }
        ]
      }
    ]
  }
}
`))
