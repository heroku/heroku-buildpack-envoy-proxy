package heroku

import (
	"encoding/json"
	"io"
	"log"
	"strings"
)

type AppEvent struct {
	ID        string   // e.g. AppID
	Hostnames []string // e.g. all the list of domains for the app
	Cert, Key string   // the single cert for the app
}

type Feed struct {
	AppID  string
	Reader io.Reader
}

func (f *Feed) Start() <-chan map[string]AppEvent {
	ch := make(chan map[string]AppEvent)

	go func() {
		defer close(ch)

		events := make(map[string]AppEvent)
		dec := json.NewDecoder(f.Reader)

		for {
			var e Entry
			err := dec.Decode(&e)
			if err == io.EOF {
				return
			}

			if err != nil {
				log.Printf("err = %s", err)
			}

			if e.Domain == nil || e.Domain.Certs == nil {
				continue
			}

			if !strings.HasSuffix(e.Domain.AppID, f.AppID) {
				continue
			}

			if _, ok := events[e.Domain.AppID]; !ok {
				events[e.Domain.AppID] = AppEvent{
					ID:        e.Domain.AppID,
					Hostnames: []string{e.Domain.Hostname},
					Cert:      e.Domain.Cert(),
					Key:       e.Domain.Key(),
				}
				continue
			}

			evs := events[e.Domain.AppID]

			evs.Hostnames = append(evs.Hostnames, e.Domain.Hostname)
			evs.Cert = e.Domain.Cert()
			evs.Key = e.Domain.Key()

			events[e.Domain.AppID] = evs

			ch <- events
		}
	}()

	return ch
}

type Entry struct {
	App    *App    `json:"App,omitempty"`
	Domain *Domain `json:"Domain,omitempty"`
	Dyno   *Dyno   `json:"Dyno,omitempty"`
}

type App struct {
	ID                 string   `json:"ID"`
	HerokuLogInputURL  string   `json:"HerokuLogInputURL"`
	LogDrainURLs       []string `json:"LogDrainURLs"`
	Maintenance        bool     `json:"Maintenance"`
	InternalLogging    bool     `json:"InternalLogging"`
	MaintenancePageURL string   `json:"MaintenancePageURL"`
	ErrorPageURL       string   `json:"ErrorPageURL"`
	Features           []string `json:"Features"`
}

type Certs struct {
	ID      string `json:"id"`
	CaCerts string `json:"cacerts"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
}

func (c *Certs) Equal(other *Certs) bool {
	if c == nil && other == nil {
		return true
	}

	if c == nil || other == nil {
		return false
	}

	return c.ID == other.ID &&
		c.CaCerts == other.CaCerts &&
		c.Cert == other.Cert &&
		c.Key == other.Key
}

type Domain struct {
	ID       string `json:"ID"`
	Hostname string `json:"Hostname"`
	AppID    string `json:"AppID"`
	Certs    *Certs `json:"Certs"`
}

func (d Domain) Equal(other Domain) bool {
	switch {
	case d.ID != other.ID:
		return false
	case d.Hostname != other.Hostname:
		return false
	case d.AppID != other.AppID:
		return false
	case !d.Certs.Equal(other.Certs):
		return false
	}

	return true
}

func (d Domain) Cert() string {
	if d.Certs == nil {
		return ""
	}
	return d.Certs.Cert + d.Certs.CaCerts
}

func (d Domain) Key() string {
	if d.Certs == nil {
		return ""
	}
	return d.Certs.Key
}

type Dyno struct {
	ID        string `json:"ID"`
	Name      string `json:"Name"`
	AppID     string `json:"AppID"`
	ProcessID int    `json:"ProcessID"`
	ReleaseID string `json:"ReleaseID"`
	Status    string `json:"Status"`
	Instance  struct {
		IPAddress string `json:"IPAddress"`
		Port      string `json:"Port"`
	} `json:"Instance"`
}
