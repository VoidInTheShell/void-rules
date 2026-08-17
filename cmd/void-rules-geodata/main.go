// SPDX-License-Identifier: MIT
// void-rules-geodata provides strict JSONL <-> V2Ray/Xray geodata conversion.
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	router "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

type record struct {
	Tag        string   `json:"tag"`
	Kind       string   `json:"kind"`
	Value      string   `json:"value"`
	Attributes []string `json:"attributes,omitempty"`
}

func usage() error {
	return errors.New("usage: void-rules-geodata <decode-geosite|encode-geosite|decode-geoip|encode-geoip|gzip> -input FILE -output FILE [-tags a,b]")
}

func gzipFile(input, output string) (returnErr error) {
	source, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("open %s: %w", input, err)
	}
	defer source.Close()
	target, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create %s: %w", output, err)
	}
	defer func() {
		if err := target.Close(); returnErr == nil && err != nil {
			returnErr = err
		}
	}()
	archive, err := gzip.NewWriterLevel(target, gzip.BestCompression)
	if err != nil {
		return err
	}
	archive.Header.ModTime = time.Unix(0, 0).UTC()
	archive.Header.OS = 255
	if _, err := io.Copy(archive, source); err != nil {
		_ = archive.Close()
		return err
	}
	if err := archive.Close(); err != nil {
		return err
	}
	return nil
}

func readBytes(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

func writeBytes(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func selectedTags(raw string) map[string]struct{} {
	selected := map[string]struct{}{}
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(strings.ToLower(item)); item != "" {
			selected[item] = struct{}{}
		}
	}
	return selected
}

func tagSelected(selected map[string]struct{}, tag string) bool {
	if len(selected) == 0 {
		return true
	}
	_, ok := selected[strings.ToLower(tag)]
	return ok
}

func writeJSONL(path string, records []record) error {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Tag != records[j].Tag {
			return records[i].Tag < records[j].Tag
		}
		if records[i].Kind != records[j].Kind {
			return records[i].Kind < records[j].Kind
		}
		return records[i].Value < records[j].Value
	})
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, item := range records {
		payload, err := json.Marshal(item)
		if err != nil {
			return err
		}
		if _, err := writer.Write(append(payload, '\n')); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func readJSONL(path string) ([]record, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	var records []record
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 16*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var item record
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, line, err)
		}
		item.Tag = strings.ToLower(strings.TrimSpace(item.Tag))
		item.Kind = strings.ToLower(strings.TrimSpace(item.Kind))
		item.Value = strings.TrimSpace(item.Value)
		if item.Tag == "" || item.Kind == "" || item.Value == "" {
			return nil, fmt.Errorf("%s line %d: tag, kind and value are required", path, line)
		}
		sort.Strings(item.Attributes)
		records = append(records, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func decodeGeosite(input, output, tags string) error {
	data, err := readBytes(input)
	if err != nil {
		return err
	}
	list := new(router.GeoSiteList)
	if err := proto.Unmarshal(data, list); err != nil {
		return fmt.Errorf("decode geosite protobuf: %w", err)
	}
	selected := selectedTags(tags)
	var records []record
	for _, site := range list.Entry {
		tag := strings.ToLower(site.CountryCode)
		if !tagSelected(selected, tag) {
			continue
		}
		for _, domain := range site.Domain {
			kind := ""
			switch domain.Type {
			case router.Domain_RootDomain:
				kind = "domain_suffix"
			case router.Domain_Full:
				kind = "domain"
			case router.Domain_Plain:
				kind = "domain_keyword"
			case router.Domain_Regex:
				kind = "domain_regex"
			default:
				return fmt.Errorf("tag %s: unknown domain enum %d", tag, domain.Type)
			}
			attributes := make([]string, 0, len(domain.Attribute))
			for _, attribute := range domain.Attribute {
				attributes = append(attributes, attribute.Key)
			}
			records = append(records, record{Tag: tag, Kind: kind, Value: domain.Value, Attributes: attributes})
		}
	}
	return writeJSONL(output, records)
}

func encodeGeosite(input, output string) error {
	records, err := readJSONL(input)
	if err != nil {
		return err
	}
	grouped := map[string][]*router.Domain{}
	for _, item := range records {
		domainType := router.Domain_RootDomain
		switch item.Kind {
		case "domain_suffix":
			domainType = router.Domain_RootDomain
		case "domain":
			domainType = router.Domain_Full
		case "domain_keyword":
			domainType = router.Domain_Plain
		case "domain_regex":
			domainType = router.Domain_Regex
		default:
			return fmt.Errorf("tag %s: unsupported geosite kind %q", item.Tag, item.Kind)
		}
		attributes := make([]*router.Domain_Attribute, 0, len(item.Attributes))
		for _, key := range item.Attributes {
			attributes = append(attributes, &router.Domain_Attribute{
				Key: key,
				TypedValue: &router.Domain_Attribute_BoolValue{
					BoolValue: true,
				},
			})
		}
		grouped[item.Tag] = append(grouped[item.Tag], &router.Domain{Type: domainType, Value: item.Value, Attribute: attributes})
	}
	tags := make([]string, 0, len(grouped))
	for tag := range grouped {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	list := &router.GeoSiteList{}
	for _, tag := range tags {
		domains := grouped[tag]
		sort.Slice(domains, func(i, j int) bool {
			if domains[i].Type != domains[j].Type {
				return domains[i].Type < domains[j].Type
			}
			return domains[i].Value < domains[j].Value
		})
		list.Entry = append(list.Entry, &router.GeoSite{CountryCode: strings.ToUpper(tag), Domain: domains})
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(list)
	if err != nil {
		return err
	}
	return writeBytes(output, payload)
}

func decodeGeoIP(input, output, tags string) error {
	data, err := readBytes(input)
	if err != nil {
		return err
	}
	list := new(router.GeoIPList)
	if err := proto.Unmarshal(data, list); err != nil {
		return fmt.Errorf("decode geoip protobuf: %w", err)
	}
	selected := selectedTags(tags)
	var records []record
	for _, entry := range list.Entry {
		tag := strings.ToLower(entry.CountryCode)
		if !tagSelected(selected, tag) {
			continue
		}
		for _, cidr := range entry.Cidr {
			address, ok := netip.AddrFromSlice(cidr.Ip)
			if !ok {
				return fmt.Errorf("tag %s: invalid IP bytes", tag)
			}
			if int(cidr.Prefix) > address.BitLen() {
				return fmt.Errorf("tag %s: invalid prefix %d", tag, cidr.Prefix)
			}
			prefix := netip.PrefixFrom(address, int(cidr.Prefix)).Masked()
			records = append(records, record{Tag: tag, Kind: "ip_cidr", Value: prefix.String()})
		}
	}
	return writeJSONL(output, records)
}

func encodeGeoIP(input, output string) error {
	records, err := readJSONL(input)
	if err != nil {
		return err
	}
	grouped := map[string][]*router.CIDR{}
	for _, item := range records {
		if item.Kind != "ip_cidr" {
			return fmt.Errorf("tag %s: unsupported geoip kind %q", item.Tag, item.Kind)
		}
		prefix, err := netip.ParsePrefix(item.Value)
		if err != nil {
			return fmt.Errorf("tag %s: invalid CIDR %q: %w", item.Tag, item.Value, err)
		}
		prefix = prefix.Masked()
		grouped[item.Tag] = append(grouped[item.Tag], &router.CIDR{Ip: prefix.Addr().AsSlice(), Prefix: uint32(prefix.Bits())})
	}
	tags := make([]string, 0, len(grouped))
	for tag := range grouped {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	list := &router.GeoIPList{}
	for _, tag := range tags {
		cidrs := grouped[tag]
		sort.Slice(cidrs, func(i, j int) bool {
			left, _ := netip.AddrFromSlice(cidrs[i].Ip)
			right, _ := netip.AddrFromSlice(cidrs[j].Ip)
			if left.Compare(right) != 0 {
				return left.Less(right)
			}
			return cidrs[i].Prefix < cidrs[j].Prefix
		})
		list.Entry = append(list.Entry, &router.GeoIP{CountryCode: strings.ToUpper(tag), Cidr: cidrs})
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(list)
	if err != nil {
		return err
	}
	return writeBytes(output, payload)
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	input := flags.String("input", "", "input path")
	output := flags.String("output", "", "output path")
	tags := flags.String("tags", "", "comma-separated tags to export")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *input == "" || *output == "" {
		return usage()
	}
	switch command {
	case "decode-geosite":
		return decodeGeosite(*input, *output, *tags)
	case "encode-geosite":
		return encodeGeosite(*input, *output)
	case "decode-geoip":
		return decodeGeoIP(*input, *output, *tags)
	case "encode-geoip":
		return encodeGeoIP(*input, *output)
	case "gzip":
		return gzipFile(*input, *output)
	default:
		return usage()
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "void-rules-geodata:", err)
		os.Exit(1)
	}
}
