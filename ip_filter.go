package caddy_ip_filter

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// init Register the module
func init() {
	caddy.RegisterModule(IPFilter{})
	httpcaddyfile.RegisterHandlerDirective("ip_filter", parseCaddyfile)
}

type IPFilter struct {
	allowedIPs  []string
	blockedIPs  []string
	Interval    caddy.Duration `json:"interval,omitempty"`
	Timeout     caddy.Duration `json:"timeout,omitempty"`
	BlockIPList string         `json:"block_ip_list,omitempty"`
	AllowIPList string         `json:"allow_ip_list,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule Return information of Caddy module
func (IPFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ip_filter",
		New: func() caddy.Module { return new(IPFilter) },
	}
}

// Provision Implemented caddy.Provisioner
func (ipf *IPFilter) Provision(ctx caddy.Context) error {
	ipf.ctx = ctx
	ipf.logger = ctx.Logger(ipf)

	if ipf.Interval == 0 {
		ipf.Interval = caddy.Duration(time.Hour)
	}

	if err := ipf.updateLists(); err != nil {
		return fmt.Errorf("updating IP lists: %v", err)
	}

	ticker := time.NewTicker(time.Duration(ipf.Interval))
	go func() {
		for range ticker.C {
			ipf.logger.Debug("Start updating IP lists")
			_ = ipf.updateLists()
			ipf.logger.Debug("Finish updating IP lists")
		}
	}()

	return nil
}

// Validate Implemented caddy.Validator
func (ipf *IPFilter) Validate() error {
	if ipf.BlockIPList == "" && ipf.AllowIPList == "" {
		return fmt.Errorf("either block_ip_url or allow_ip_url must be specified")
	}
	return nil
}

// ServeHTTP Implemented caddyhttp.MiddlewareHandler
func (ipf IPFilter) ServeHTTP(w http.ResponseWriter, r *http.Request,
	next caddyhttp.Handler) error {
	// Get client IP address
	clientIP := getRealIP(r)

	ipf.logger.Debug("Client IP", zap.String("ip", clientIP))

	ip := net.ParseIP(clientIP)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return nil
	}

	// Check if it is on the allow list
	if isIPInList(ip, ipf.allowedIPs) {
		ipf.logger.Info("Access allowed", zap.String("ip", clientIP))
		return next.ServeHTTP(w, r) // Continue to next process
	}

	// Check if it is on the block list
	if isIPInList(ip, ipf.blockedIPs) {
		ipf.logger.Info("Access blocked", zap.String("ip", clientIP))
		http.Error(w, "Access denied", http.StatusForbidden)
		return nil
	}

	// Default process
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile Implemented caddyfile.Unmarshaler
func (ipf *IPFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				ipf.Interval = caddy.Duration(val)
			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				ipf.Timeout = caddy.Duration(val)
			case "block_ip_list":
				if !d.Args(&ipf.BlockIPList) {
					return d.ArgErr()
				}
			case "allow_ip_list":
				if !d.Args(&ipf.AllowIPList) {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// updateLists Retrieve IP and CIDR lists from API
func (ipf *IPFilter) updateLists() error {
	if ipf.BlockIPList != "" {
		if isURL(ipf.BlockIPList) {
			// If it is a URL, retrieve the list from the API
			var err error
			ipf.blockedIPs, err = ipf.fetch(ipf.BlockIPList)
			if err != nil {
				ipf.logger.Error("Failed to fetch block list", zap.Error(err))
				return err
			}
		} else {
			// If it's not a URL, it's a file path
			data, err := os.ReadFile(ipf.BlockIPList)
			if err != nil {
				ipf.logger.Error("Failed to read block list", zap.Error(err))
				return err
			}

			ipf.blockedIPs = strings.Split(string(data), "\n")
		}
	}

	if ipf.AllowIPList != "" {
		if isURL(ipf.AllowIPList) {
			// If it is a URL, retrieve the list from the API
			var err error
			ipf.allowedIPs, err = ipf.fetch(ipf.AllowIPList)
			if err != nil {
				ipf.logger.Error("Failed to fetch allow list", zap.Error(err))
				return err
			}
		} else {
			// If it's not a URL, it's a file path
			data, err := os.ReadFile(ipf.AllowIPList)
			if err != nil {
				ipf.logger.Error("Failed to read allow list", zap.Error(err))
				return err
			}

			ipf.allowedIPs = strings.Split(string(data), "\n")
		}
	}

	return nil
}

// getContext
func (ipf *IPFilter) getContext() (context.Context, context.CancelFunc) {
	if ipf.Timeout > 0 {
		return context.WithTimeout(ipf.ctx, time.Duration(ipf.Timeout))
	}
	return context.WithCancel(ipf.ctx)
}

// fetch Retrieve IP and CIDR lists from API
func (ipf *IPFilter) fetch(api string) ([]string, error) {
	ctx, cancel := ipf.getContext()
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return strings.Split(string(body), "\n"), nil
}

// getRealIP get real IP address
func getRealIP(r *http.Request) string {
	// Check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can multiple IP addresses, separated by commas
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// return to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// isURL Check if the string is a URL
func isURL(str string) bool {
	regex := `^(http|https)://[^\s/$.?#].[^\s]*$`
	re := regexp.MustCompile(regex)
	return re.MatchString(str)
}

// isIPInList Check if the IP is in the list
func isIPInList(ip net.IP, list []string) bool {
	for _, entry := range list {
		entry = strings.TrimSpace(entry) // Remove spaces

		// Try parse to IP
		if net.ParseIP(entry) != nil {
			if ip.Equal(net.ParseIP(entry)) {
				return true
			}
		} else {
			// Try parse to CIDR
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// parseCaddyfile parsing Caddyfile
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ipf IPFilter
	err := ipf.UnmarshalCaddyfile(h.Dispenser)
	return ipf, err
}

// Ensure the implementation of IPFilter interface
var (
	_ caddy.Provisioner           = (*IPFilter)(nil)
	_ caddy.Validator             = (*IPFilter)(nil)
	_ caddyhttp.MiddlewareHandler = (*IPFilter)(nil)
	_ caddyfile.Unmarshaler       = (*IPFilter)(nil)
)
