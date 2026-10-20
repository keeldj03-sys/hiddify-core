package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// The Flutter app sends routing rules as protobuf JSON (RouteRule.toProto3Json):
// field names are the proto json_name values ("rule_set", "domain_suffix", ...)
// and enums are serialized as their lowercase value names ("block", "direct").
// The generated Go struct instead expects its own json tags ("rule_sets") and
// numeric enums. UnmarshalJSON bridges the two so both formats decode.
func (r *Rule) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// proto json_name first (what the app sends), Go tag as fallback
	lookup := func(names ...string) (json.RawMessage, bool) {
		for _, n := range names {
			if v, ok := raw[n]; ok {
				return v, true
			}
		}
		return nil, false
	}
	getString := func(dst *[]string, names ...string) error {
		v, ok := lookup(names...)
		if !ok {
			return nil
		}
		var arr []string
		if err := json.Unmarshal(v, &arr); err != nil {
			return fmt.Errorf("field %s: %w", names[0], err)
		}
		*dst = arr
		return nil
	}

	if v, ok := lookup("list_order"); ok {
		if err := json.Unmarshal(v, &r.ListOrder); err != nil {
			return err
		}
	}
	if v, ok := lookup("enabled"); ok {
		if err := json.Unmarshal(v, &r.Enabled); err != nil {
			return err
		}
	}
	if v, ok := lookup("name"); ok {
		if err := json.Unmarshal(v, &r.Name); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		names []string
		out   *[]string
	}{
		{[]string{"rule_set", "rule_sets"}, &r.RuleSets},
		{[]string{"package_name", "package_names"}, &r.PackageNames},
		{[]string{"process_name", "process_names"}, &r.ProcessNames},
		{[]string{"process_path", "process_paths"}, &r.ProcessPaths},
		{[]string{"port_range", "port_ranges"}, &r.PortRanges},
		{[]string{"source_port_range", "source_port_ranges"}, &r.SourcePortRanges},
		{[]string{"ip_cidr", "ip_cidrs"}, &r.IpCidrs},
		{[]string{"source_ip_cidr", "source_ip_cidrs"}, &r.SourceIpCidrs},
		{[]string{"domain", "domains"}, &r.Domains},
		{[]string{"domain_suffix", "domain_suffixes"}, &r.DomainSuffixes},
		{[]string{"domain_keyword", "domain_keywords"}, &r.DomainKeywords},
		{[]string{"domain_regex", "domain_regexes"}, &r.DomainRegexes},
	} {
		if err := getString(f.out, f.names...); err != nil {
			return err
		}
	}
	if v, ok := lookup("outbound"); ok {
		out, err := decodeOutbound(v)
		if err != nil {
			return err
		}
		r.Outbound = out
	}
	if v, ok := lookup("network"); ok {
		net, err := decodeNetwork(v)
		if err != nil {
			return err
		}
		r.Network = net
	}
	if v, ok := lookup("protocol", "protocols"); ok {
		protocols, err := decodeProtocols(v)
		if err != nil {
			return err
		}
		r.Protocols = protocols
	}
	return nil
}

func decodeEnum(value json.RawMessage, values map[string]int32, kind string) (int32, error) {
	var s string
	if err := json.Unmarshal(value, &s); err == nil {
		if n, ok := values[strings.ToLower(s)]; ok {
			return n, nil
		}
		return 0, fmt.Errorf("unknown %s %q", kind, s)
	}
	var n int32
	if err := json.Unmarshal(value, &n); err != nil {
		return 0, fmt.Errorf("invalid %s: %w", kind, err)
	}
	return n, nil
}

func decodeOutbound(value json.RawMessage) (Outbound, error) {
	n, err := decodeEnum(value, Outbound_value, "outbound")
	if err != nil {
		return 0, err
	}
	return Outbound(n), nil
}

func decodeNetwork(value json.RawMessage) (Network, error) {
	n, err := decodeEnum(value, Network_value, "network")
	if err != nil {
		return 0, err
	}
	return Network(n), nil
}

func decodeProtocols(value json.RawMessage) ([]Protocol, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(value, &arr); err != nil {
		return nil, fmt.Errorf("invalid protocols: %w", err)
	}
	protocols := make([]Protocol, 0, len(arr))
	for _, el := range arr {
		n, err := decodeEnum(el, Protocol_value, "protocol")
		if err != nil {
			return nil, err
		}
		protocols = append(protocols, Protocol(n))
	}
	return protocols, nil
}
