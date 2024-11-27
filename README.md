# ip filter module for caddy

This module implements request IP filter

## Features

- Support IPv4
- Support IPv6
- Support single IP address. Like 192.168.0.1
- Support IP address range. Like 192.168.0.0/32
- Support `X-Forwarded-For`
- support `X-Real-IP`

## Format

```
1.1.1.1
8.8.8.8
103.31.200.0/22
103.218.216.0/22
2405:f080:1000::/38
2405:f080:1400::/47
```

## Caddyfile

```
:80 {
    route {
        ip_filter {
            # allow_ip_list https://example.com/allow_ips.txt
            # block_ip_list https://example.com/block_ips.txt
            allow_ip_list /var/allow_ips.txt
            block_ip_list /var/block_ips.txt
            interval 1h
            timeout 10s
        }

        reverse_proxy localhost:8080
    }

    log {
        output file /var/log/caddy/test.log
    }
}
```

## Parameters

| Name          | Description                                         | Type     | Default    |
| ------------- | --------------------------------------------------- | -------- | ---------- |
| interval      | Update Interval                                     | duration | 1h         |
| timeout       | Maximum time to wait to get a response from network | duration | no timeout |
| allow_ip_list | List of allowed IP addresses (Local path or URL)    | string   | none       |
| block_ip_list | List of blocked IP addresses (Local path or URL)    | string   | none       |
