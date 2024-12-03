package caddy_ip_filter

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestDefault(t *testing.T) {
	blockIPList := "blockIPList.txt"
	allowIPList := "allowIPList.txt"
	config := fmt.Sprintf(`ipfilter {
		interval 1h
		timeout 10s
		block_ip_list %s
		allow_ip_list %s
	}`, blockIPList, allowIPList)

	d := caddyfile.NewTestDispenser(config)

	r := IPFilter{}
	err := r.UnmarshalCaddyfile(d)
	if err != nil {
		t.Errorf("unmarshal error for %q: %v", config, err)
		return
	}

	if r.BlockIPList != blockIPList {
		t.Errorf("expected block_ip_list to be %q, got %q", blockIPList, r.BlockIPList)
	}

	if r.AllowIPList != allowIPList {
		t.Errorf("expected allow_ip_list to be %q, got %q", allowIPList, r.AllowIPList)
	}

	if r.Interval != caddy.Duration(1*time.Hour) {
		t.Errorf("expected interval to be 1h, got %v", r.Interval)
	}

	if r.Timeout != caddy.Duration(10*time.Second) {
		t.Errorf("expected timeout to be 10s, got %v", r.Timeout)
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err = r.Provision(ctx)
	if err != nil {
		t.Errorf("error provisioning %q: %v", config, err)
	}

	if r.blockedIPs == nil {
		t.Errorf("expected blockedIPs to be initialized")
	}

	if r.allowedIPs == nil {
		t.Errorf("expected allowedIPs to be initialized")
	}

	// 测试是否在列表中
	ip := net.ParseIP("1.1.1.1")
	if !isIPInList(ip, r.blockedIPs) {
		t.Errorf("expected %q to be in blockedIPs", ip)
	}
}
