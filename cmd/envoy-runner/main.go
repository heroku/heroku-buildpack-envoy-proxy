package main

import (
	"encoding/json"
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

	"golang.org/x/sync/errgroup"
)

const (
	feedReadTimeout = 5 * time.Second
	appPort         = "8080"
	acmRedirectPort = "8081"
	acmURL          = "https://va-acm.heroku.com/challenge"
	acmPathPrefix   = "/.well-known/acme-challenge/"
)

var config = struct {
	AppID string

	RouterPlainPort       string
	RouterTLSPort         string
	RouterHealthcheckPort string
}{
	AppID:                 os.Getenv("APP_ID"),
	RouterPlainPort:       os.Getenv("HEROKU_ROUTER_HTTP_PORT"),
	RouterTLSPort:         os.Getenv("HEROKU_ROUTER_HTTPS_PORT"),
	RouterHealthcheckPort: os.Getenv("HEROKU_ROUTER_HEALTHCHECK_PORT"),
}

func main() {
	if config.RouterPlainPort == "" || config.RouterTLSPort == "" {
		fmt.Fprintf(os.Stderr, "envoy-daemon only works with spaces-router-bypass\n")
		os.Exit(0)
	}

	cert, key, err := setupTLS(config.AppID)
	if err != nil {
		log.Fatal(err)
	}

	if cert != nil && key != nil {
		if err := ioutil.WriteFile("/tmp/cert.crt", cert, 0600); err != nil {
			log.Fatal(err)
		}

		if err := ioutil.WriteFile("/tmp/cert.key", key, 0600); err != nil {
			log.Fatal(err)
		}
	}

	file, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	err = configTemplate.Execute(file, struct {
		PlaintextPort           string
		TLSPort                 string
		AppPort                 string
		AcmRedirectPort         string
		ACMEChallengePathPrefix string
		HasTLS                  bool
	}{
		config.RouterPlainPort,
		config.RouterTLSPort,
		appPort,
		acmRedirectPort,
		acmPathPrefix,
		cert != nil && key != nil,
	})
	if err != nil {
		log.Fatal(err)
	}

	g := new(errgroup.Group)

	g.Go(func() error {
		srv := &tcpServer{port: config.RouterHealthcheckPort}
		return srv.run()
	})

	g.Go(func() error {
		acmURL, err := url.Parse(acmURL)
		if err != nil {
			return err
		}

		http.HandleFunc(acmPathPrefix, func(w http.ResponseWriter, r *http.Request) {
			qs := url.Values{}
			qs.Set("token", strings.TrimPrefix(r.URL.Path, acmPathPrefix))
			qs.Set("host", r.Host)

			u := *acmURL
			u.RawQuery = qs.Encode()
			http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
		})

		return http.ListenAndServe(fmt.Sprintf(":%s", acmRedirectPort), nil)
	})

	g.Go(func() error {
		cmd := exec.Command("envoy", "-c", file.Name())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	})

	log.Fatal(g.Wait())
}

func setupTLS(appID string) (cert, key []byte, err error) {
	res, err := http.Get(os.Getenv("HEROKU_ROUTER_FEED_URL"))
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	dec := json.NewDecoder(res.Body)

	ch := make(chan entry)
	go func() {
		for {
			var e entry
			if err := dec.Decode(&e); err != nil {
				return
			}

			if strings.HasSuffix(e.Domain.AppID, appID) && e.hasCert() {
				ch <- e
			}
		}
	}()

CacheLoop:
	for {
		select {
		case <-time.After(feedReadTimeout):
			break CacheLoop
		case e := <-ch:
			cert, key = e.Cert(), e.Key()
		}
	}

	return cert, key, nil
}

type entry struct {
	Domain struct {
		Hostname string `json:"Hostname"`
		AppID    string `json:"AppID"`
		Certs    struct {
			ID      string `json:"id"`
			CaCerts string `json:"cacerts"`
			Cert    string `json:"cert"`
			Key     string `json:"key"`
		} `json:"Certs"`
	} `json:"Domain"`
}

func (e entry) String() string {
	return fmt.Sprintf("hostname=%s app_id=%s cert_id=%s", e.Domain.Hostname, e.Domain.AppID, e.Domain.Certs.ID)
}

func (e entry) Cert() []byte {
	return []byte(e.Domain.Certs.Cert + e.Domain.Certs.CaCerts)
}

func (e entry) Key() []byte {
	return []byte(e.Domain.Certs.Key)
}

func (e entry) hasCert() bool {
	return e.Domain.Certs.ID != ""
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
	log.Printf("at=bind port=%s", s.port)
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
				log.Printf("at=accept err=%s retrying in %s", err, retryDelay)
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
		log.Printf("err=%s", err)
	}
}

var configTemplate = template.Must(template.New("config").Parse(`
{
  "admin": {
    "access_log_path": "/tmp/admin_access.log",
    "address": {
      "socket_address": {
        "protocol": "TCP",
        "address": "127.0.0.1",
        "port_value": 9901
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
            "use_proxy_proto": true,
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
                              "prefix": "{{.ACMEChallengePathPrefix}}"
                            },
                            "route": {
                              "cluster": "acm_redirect_service"
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
      },
      {{ if .HasTLS }}
      {
        "name": "tls_listener",
        "address": {
          "socket_address": {
            "address": "0.0.0.0",
            "port_value": {{.TLSPort}}
          }
        },
        "filter_chains": [
          {
            "use_proxy_proto": true,
            "tls_context": {
              "common_tls_context": {
                "tls_certificates": {
                  "certificate_chain": {
                    "filename": "/tmp/cert.crt"
                  },
                  "private_key": {
                    "filename": "/tmp/cert.key"
                  }
                }
              }
            },
            "filters": [
              {
                "name": "envoy.http_connection_manager",
                "config": {
                  "codec_type": "auto",
                  "stat_prefix": "ingress_https",
                  "route_config": {
                    "name": "local_route",
                    "virtual_hosts": [
                      {
                        "name": "backend",
                        "domains": ["*"],
                        "routes": [
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
      {{ end }}
    ],
    "clusters": [
      {
        "name": "local_service",
        "connect_timeout": "0.25s",
        "type": "strict_dns",
        "lb_policy": "round_robin",
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
        "name": "acm_redirect_service",
        "connect_timeout": "0.25s",
        "type": "strict_dns",
        "lb_policy": "round_robin",
        "hosts": [
          {
            "socket_address": {
              "address": "127.0.0.1",
              "port_value": {{.AcmRedirectPort}}
            }
          }
        ]
      }
    ]
  }
}
`))

type Config struct {
	Admin struct {
		AccessLogPath string `json:"access_log_path"`
		Address       struct {
			SocketAddress struct {
				Protocol  string `json:"protocol"`
				Address   string `json:"address"`
				PortValue int    `json:"port_value"`
			} `json:"socket_address"`
		} `json:"address"`
	} `json:"admin"`
	StaticResources struct {
		Listeners []struct {
			Name    string `json:"name"`
			Address struct {
				SocketAddress struct {
					Address   string `json:"address"`
					PortValue int    `json:"port_value"`
				} `json:"socket_address"`
			} `json:"address"`
			FilterChains []struct {
				UseProxyProto bool `json:"use_proxy_proto"`

				TLSContext *struct {
					CommonTLSContext struct {
						TLSCertificates struct {
							CertificateChain struct {
								Filename string `json:"filename"`
							} `json:"certificate_chain"`
							PrivateKey struct {
								Filename string `json:"filename"`
							} `json:"private_key"`
						} `json:"tls_certificates"`
					} `json:"common_tls_context"`
				} `json:"tls_context,omitempty"`

				Filters []struct {
					Name   string `json:"name"`
					Config struct {
						CodecType   string `json:"codec_type"`
						StatPrefix  string `json:"stat_prefix"`
						RouteConfig struct {
							Name         string `json:"name"`
							VirtualHosts []struct {
								Name    string   `json:"name"`
								Domains []string `json:"domains"`
								Routes  []struct {
									Match struct {
										Prefix string `json:"prefix"`
									} `json:"match"`
									Route struct {
										Cluster string `json:"cluster"`
									} `json:"route"`
								} `json:"routes"`
							} `json:"virtual_hosts"`
						} `json:"route_config"`
						HTTPFilters []struct {
							Name   string `json:"name"`
							Config struct {
							} `json:"config"`
						} `json:"http_filters"`
					} `json:"config"`
				} `json:"filters"`
			} `json:"filter_chains"`
		} `json:"listeners"`
		Clusters []struct {
			Name           string `json:"name"`
			ConnectTimeout string `json:"connect_timeout"`
			Type           string `json:"type"`
			LbPolicy       string `json:"lb_policy"`
			Hosts          []struct {
				SocketAddress struct {
					Address   string `json:"address"`
					PortValue int    `json:"port_value"`
				} `json:"socket_address"`
			} `json:"hosts"`
		} `json:"clusters"`
	} `json:"static_resources"`
}
