package config

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// Rule-set sources. The Hiddify repository hosts block lists and per-country
// sets; SagerNet repositories are the fallback for arbitrary geosite-/geoip-
// tags (e.g. geosite-telegram).
const (
	hiddifyGeoBase  = "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/"
	singGeositeBase = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/"
	singGeoipBase   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/"
)

// dnsRCodeRefused is the DNS response code "REFUSED" (5).
//
// It is spelled out here instead of taken from github.com/sagernet/sing-dns:
// that module is built against an older sing, and its API does not match the
// one this core uses.
const dnsRCodeRefused = 5

// countries hosted at <hiddifyGeoBase>country/.
var hiddifyGeoCountries = map[string]struct{}{
	"af": {}, "br": {}, "cn": {}, "id": {}, "ir": {}, "ru": {}, "tr": {},
}

// blockTags hosted at <hiddifyGeoBase>block/.
var hiddifyGeoBlockTags = map[string]struct{}{
	"geosite-category-ads-all": {},
	"geosite-malware":          {},
	"geosite-phishing":         {},
	"geosite-cryptominers":     {},
	"geoip-malware":            {},
	"geoip-phishing":           {},
}

// ruleSetURL resolves a rule-set tag (as used in user routing rules) to a
// remote .srs download URL. Returns ok=false for tags without a known
// source; the caller must skip such tags instead of emitting a rule-set
// reference that would fail to download.
func ruleSetURL(tag string) (url string, ok bool) {
	if strings.HasPrefix(tag, "http://") || strings.HasPrefix(tag, "https://") {
		return tag, true
	}
	if _, ok := hiddifyGeoBlockTags[tag]; ok {
		return hiddifyGeoBase + "block/" + tag + ".srs", true
	}
	if strings.HasPrefix(tag, "geosite-") {
		if _, ok := hiddifyGeoCountries[strings.TrimPrefix(tag, "geosite-")]; ok {
			return hiddifyGeoBase + "country/" + tag + ".srs", true
		}
		return singGeositeBase + tag + ".srs", true
	}
	if strings.HasPrefix(tag, "geoip-") {
		if _, ok := hiddifyGeoCountries[strings.TrimPrefix(tag, "geoip-")]; ok {
			return hiddifyGeoBase + "country/" + tag + ".srs", true
		}
		return singGeoipBase + tag + ".srs", true
	}
	return "", false
}

// MakeRouteRule converts a user routing rule (protobuf Rule) into a sing-box
// route rule. tags is the list of rule-set tags to reference, already
// validated (resolvable to a remote .srs URL) by the caller.
func (r *Rule) MakeRouteRule(tags []string) (rule option.Rule, ok bool) {
	raw := option.RawDefaultRule{
		Domain:          r.Domains,
		DomainSuffix:    r.DomainSuffixes,
		DomainKeyword:   r.DomainKeywords,
		DomainRegex:     r.DomainRegexes,
		IPCIDR:          r.IpCidrs,
		SourceIPCIDR:    r.SourceIpCidrs,
		PortRange:       r.PortRanges,
		SourcePortRange: r.SourcePortRanges,
		ProcessName:     r.ProcessNames,
		ProcessPath:     r.ProcessPaths,
		PackageName:     r.PackageNames,
	}
	if r.Network != Network_all {
		raw.Network = []string{r.Network.String()}
	}
	if len(r.Protocols) > 0 {
		raw.Protocol = make([]string, 0, len(r.Protocols))
		for _, p := range r.Protocols {
			raw.Protocol = append(raw.Protocol, p.String())
		}
	}
	if len(tags) == 0 {
		probe := option.DefaultRule{RawDefaultRule: raw}
		if !probe.IsValid() {
			return option.Rule{}, false
		}
	}
	raw.RuleSet = tags

	action := option.RuleAction{Action: C.RuleActionTypeRoute}
	switch r.Outbound {
	case Outbound_direct_with_fragment:
		action.RouteOptions = option.RouteActionOptions{Outbound: OutboundDirectFragmentTag}
	case Outbound_direct:
		action.RouteOptions = option.RouteActionOptions{Outbound: OutboundDirectTag}
	case Outbound_block:
		action = option.RuleAction{
			Action:        C.RuleActionTypeReject,
			RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault},
		}
	default: // proxy
		action.RouteOptions = option.RouteActionOptions{Outbound: OutboundMainDetour}
	}

	return option.Rule{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{RawDefaultRule: raw, RuleAction: action},
	}, true
}

// MakeDNSRule mirrors a user routing rule into a DNS rule, so that DNS
// resolution follows the same routing decision (direct/blocked/proxied).
func (r *Rule) MakeDNSRule(tags []string) (rule option.DefaultDNSRule, ok bool) {
	raw := option.RawDefaultDNSRule{
		Domain:          r.Domains,
		DomainSuffix:    r.DomainSuffixes,
		DomainKeyword:   r.DomainKeywords,
		DomainRegex:     r.DomainRegexes,
		IPCIDR:          r.IpCidrs,
		SourceIPCIDR:    r.SourceIpCidrs,
		PortRange:       r.PortRanges,
		SourcePortRange: r.SourcePortRanges,
		ProcessName:     r.ProcessNames,
		ProcessPath:     r.ProcessPaths,
		PackageName:     r.PackageNames,
	}
	if r.Network != Network_all {
		raw.Network = []string{r.Network.String()}
	}
	if len(tags) == 0 {
		probe := option.DefaultDNSRule{RawDefaultDNSRule: raw}
		if !probe.IsValid() {
			return option.DefaultDNSRule{}, false
		}
	}
	raw.RuleSet = tags

	action := option.DNSRuleAction{Action: C.RuleActionTypeRoute}
	switch r.Outbound {
	case Outbound_direct, Outbound_direct_with_fragment:
		action.RouteOptions = option.DNSRouteActionOptions{Server: DNSMultiDirectTag}
	case Outbound_block:
		rcode := option.DNSRCode(dnsRCodeRefused)
		action = option.DNSRuleAction{
			Action: C.RuleActionTypePredefined,
			PredefinedOptions: option.DNSRouteActionPredefined{
				Rcode: &rcode,
			},
		}
	default: // proxy
		action.RouteOptions = option.DNSRouteActionOptions{Server: DNSMultiRemoteTag}
	}

	return option.DefaultDNSRule{RawDefaultDNSRule: raw, DNSRuleAction: action}, true
}
