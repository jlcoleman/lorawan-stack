// Copyright © 2019 The Things Network Foundation, The Things Industries B.V.
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

package cups

import (
	"context"
	"github.com/labstack/echo"
	"go.thethings.network/lorawan-stack/pkg/component"
	"go.thethings.network/lorawan-stack/pkg/ttnpb"
	"go.thethings.network/lorawan-stack/pkg/web"
)

const defaultFirmwarePath = "https://thethingsproducts.blob.core.windows.net/the-things-gateway/v1"

// Config is the configuration of the The Things Gateay CUPS server.
type Config struct {
	Default struct {
		UpdateChannel string `name:"update-channel" description:"The default update channel that the gateways should use"`
		MQTTServer    string `name:"mqtt-server" description:"The default MQTT server that the gateways should use"`
		FirmwareURL   string `name:"firmware-url" description:"The default URL to the firmware storage"`
	} `name:"default" description:"Default gateway settings"`
}

// NewServer returns a new CUPS server from this config on top of the component.
func (conf Config) NewServer(c *component.Component, customOpts ...Option) *Server {
	opts := []Option{
		WithConfig(conf),
	}
	if conf.Default.FirmwareURL == "" {
		opts = append(opts, WithDefaultFirmwareURL(defaultFirmwarePath))
	}
	s := NewServer(c, append(opts, customOpts...)...)
	c.RegisterWeb(s)
	return s
}

// Server implements the CUPS endpoints used by The Things Gateway.
type Server struct {
	component *component.Component

	registry ttnpb.GatewayRegistryClient

	config Config
}

func (s *Server) getRegistry(ctx context.Context, ids *ttnpb.GatewayIdentifiers) ttnpb.GatewayRegistryClient {
	if s.registry != nil {
		return s.registry
	}
	return ttnpb.NewGatewayRegistryClient(s.component.GetPeer(ctx, ttnpb.PeerInfo_ENTITY_REGISTRY, ids).Conn())
}

// Option configures the CUPSServer.
type Option func(s *Server)

// WithRegistry overrides the CUPS server's gateway registry.
func WithRegistry(registry ttnpb.GatewayRegistryClient) Option {
	return func(s *Server) {
		s.registry = registry
	}
}

// WithConfig overrides the CUPS server configuration.
func WithConfig(conf Config) Option {
	return func(s *Server) {
		s.config = conf
	}
}

// WithDefaultUpdateChannel overrides the default CUPS server gateway update channel.
func WithDefaultUpdateChannel(channel string) Option {
	return func(s *Server) {
		s.config.Default.UpdateChannel = channel
	}
}

// WithDefaultMQTTServer overrides the default CUPS server gateway MQTT server.
func WithDefaultMQTTServer(server string) Option {
	return func(s *Server) {
		s.config.Default.MQTTServer = server
	}
}

// WithDefaultFirmwareURL overrides the default CUPS server firmware base URL.
func WithDefaultFirmwareURL(url string) Option {
	return func(s *Server) {
		s.config.Default.FirmwareURL = url
	}
}

const compatAPIPrefix = "/api/v2"

// RegisterRoutes implements the web.Registerer interface.
func (s *Server) RegisterRoutes(srv *web.Server) {
	group := srv.Group(compatAPIPrefix)
	group.GET("/gateways/:gateway_id", func(c echo.Context) error {
		return s.handleGatewayInfo(c)
	}, []echo.MiddlewareFunc{
		s.validateAndFillGatewayIDs(),
		s.checkAuthPresence(),
	}...)
	group.GET("/frequency-plans/:frequency_plan_id", func(c echo.Context) error {
		return s.handleFreqPlanInfo(c)
	})
}

// NewServer returns a new CUPS server on top of the given gateway registry.
func NewServer(c *component.Component, options ...Option) *Server {
	s := &Server{
		component: c,
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}
