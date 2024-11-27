package caddy_ip_filter

import (
	"encoding/json"
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
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// 保证 IPFilter 实现接口
var (
	_ caddy.Provisioner     = (*IPFilter)(nil)
	_ caddy.Validator       = (*IPFilter)(nil)
	_ caddyfile.Unmarshaler = (*IPFilter)(nil)
)

// init 函数用于注册 Caddy 插件
func init() {
	caddy.RegisterModule(IPFilter{})
}

type IPFilter struct {
	logger      *zap.Logger
	allowedIPs  []string
	blockedIPs  []string
	Interval    caddy.Duration `json:"interval,omitempty"`      // 更新列表的时间间隔
	Timeout     caddy.Duration `json:"timeout,omitempty"`       // 请求超时时间
	BlockIPList string         `json:"block_ip_list,omitempty"` // 封禁列表 可以是ip列表或者CIDR列表
	AllowIPList string         `json:"allow_ip_list,omitempty"` // 放行列表 可以是ip列表或者CIDR列表
}

// CaddyModule返回Caddy模块的信息
func (IPFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ipfilter",
		New: func() caddy.Module { return new(IPFilter) },
	}
}

// Provision实现了caddy.Provisioner
func (h *IPFilter) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h) // 获取日志对象

	// 如果未设置更新间隔，则默认为1小时
	if h.Interval == 0 {
		h.Interval = caddy.Duration(time.Hour)
	}

	// 更新列表
	if err := h.updateLists(); err != nil {
		return fmt.Errorf("updating IP lists: %v", err)
	}

	// 启动定时器，定时更新列表
	ticker := time.NewTicker(time.Duration(h.Interval))
	go func() {
		for range ticker.C {
			h.logger.Debug("Start updating IP lists")
			_ = h.updateLists()
			h.logger.Debug("Finish updating IP lists")
		}
	}()

	return nil
}

// Validate实现了caddy.Validator
func (h *IPFilter) Validate() error {
	if h.BlockIPList == "" && h.AllowIPList == "" {
		return fmt.Errorf("either block_ip_url or allow_ip_url must be specified")
	}
	return nil
}

// ServeHTTP 实现了 caddyhttp.MiddlewareHandler
func (h *IPFilter) ServeHTTP(w http.ResponseWriter, r *http.Request,
	next caddyhttp.Handler) error {
	// 获取客户端IP
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}

	h.logger.Info("Client IP", zap.String("ip", clientIP))

	ip := net.ParseIP(clientIP)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return nil
	}

	// 检查是否在放行列表中
	if isIPInList(ip, h.allowedIPs) {
		h.logger.Info("Access allowed", zap.String("ip", clientIP))
		return next.ServeHTTP(w, r) // 继续执行下一个处理程序
	}

	// 检查是否在封禁列表中
	if isIPInList(ip, h.blockedIPs) {
		h.logger.Info("Access blocked", zap.String("ip", clientIP))
		http.Error(w, "Access denied", http.StatusForbidden)
		return nil
	}

	// 默认处理
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile 实现了 caddyfile.Unmarshaler
func (h *IPFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
				h.Interval = caddy.Duration(val)
			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				h.Timeout = caddy.Duration(val)
			case "block_ip_list":
				if !d.Args(&h.BlockIPList) {
					return d.ArgErr()
				}
			case "allow_ip_list":
				if !d.Args(&h.AllowIPList) {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// updateLists 从API获取IP和CIDR列表
func (h *IPFilter) updateLists() error {
	if h.BlockIPList != "" {
		if isURL(h.BlockIPList) {
			// 如果是URL，则从API获取列表
			resp, err := http.Get(h.BlockIPList)
			if err != nil {
				h.logger.Error("Failed to fetch block list", zap.Error(err))
				return err
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				h.logger.Error("Failed to read block list", zap.Error(err))
				return err
			}
			if err := json.Unmarshal(body, &h.blockedIPs); err != nil {
				h.logger.Error("Failed to parse block list", zap.Error(err))
				return err
			}
		} else {
			// 不是URL则是文件路径
			data, err := os.ReadFile(h.BlockIPList)
			if err != nil {
				h.logger.Error("Failed to read block list", zap.Error(err))
				return err
			}

			h.blockedIPs = strings.Split(string(data), "\n")
		}
	}

	if h.AllowIPList != "" {
		if isURL(h.AllowIPList) {
			resp, err := http.Get(h.AllowIPList)
			if err != nil {
				h.logger.Error("Failed to fetch allow list", zap.Error(err))
				return err
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				h.logger.Error("Failed to read allow list", zap.Error(err))
				return err
			}
			if err := json.Unmarshal(body, &h.allowedIPs); err != nil {
				h.logger.Error("Failed to parse allow list", zap.Error(err))
				return err
			}
		} else {
			// 不是URL则是文件路径
			data, err := os.ReadFile(h.AllowIPList)
			if err != nil {
				h.logger.Error("Failed to read allow list", zap.Error(err))
				return err
			}

			h.allowedIPs = strings.Split(string(data), "\n")
		}
	}

	return nil
}

// isIPInList 检查IP是否在列表中
func isIPInList(ip net.IP, list []string) bool {
	for _, entry := range list {
		entry = strings.TrimSpace(entry) // 去除空格

		// 先尝试解析为IP
		if net.ParseIP(entry) != nil {
			if ip.Equal(net.ParseIP(entry)) {
				return true
			}
		} else {
			// 尝试解析为CIDR
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				continue // 如果解析失败，跳过
			}
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// isURL 检查字符串是否为URL
func isURL(str string) bool {
	// 定义一个简单的正则表达式来匹配 URL
	// 这个正则表达式并不是非常严格，可以根据需要进行调整
	regex := `^(http|https)://[^\s/$.?#].[^\s]*$`
	re := regexp.MustCompile(regex)
	return re.MatchString(str)
}
