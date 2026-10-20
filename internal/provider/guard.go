package provider

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateBaseURL checks the URL an admin stored for a provider.
// HTTPS may point at a public host. HTTP is limited to loopback and private
// networks so a local model such as Ollama can be used without sending keys
// across the public internet or to a link-local metadata address.
func ValidateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("provider: invalid URL")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("provider: URL needs a host")
	}
	if u.User != nil {
		return fmt.Errorf("provider: URL must not contain credentials")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		return validateHTTPHost(u.Hostname())
	default:
		return fmt.Errorf("provider: URL scheme must be https or http")
	}
}

func validateHTTPHost(host string) error {
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("provider: http is only allowed for localhost and private IP addresses")
	}
	ip = normalizeIP(ip)
	if ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	return fmt.Errorf("provider: http is only allowed for localhost and private IP addresses")
}

func ipAllowed(ip net.IP) bool {
	ip = normalizeIP(ip)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// 169.254.0.0/16 is link-local and includes cloud metadata addresses.
	if v4 := ip.To4(); v4 != nil && v4[0] == 169 && v4[1] == 254 {
		return false
	}
	return true
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
