package main

import (
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

type DNSCache interface {
	GetPublicFromDNS(dns string, path []string) (err error, mpk string, public []string)
}

type _DNSCache struct {
	// map from full DNS -> map
	// cache[domain][node][key]
	Cache map[string]map[string]map[string]string
}

func NewDNSCache() DNSCache {
	var retval _DNSCache

	// cache[domain][node][key]
	retval.Cache = make(map[string]map[string]map[string]string)

	return &retval
}

func dnsTXTQuery(query string) string {
	txt, err2 := net.LookupTXT(query)
	tryCount := 0

	for tryCount < 4 && err2 != nil {
		time.Sleep(BACKOFF_TIME)
		txt2, err2 := net.LookupTXT(query)
		if err2 != nil {
			log.Printf("DNS ERROR", err2)
			return ""
		}
		txt = txt2
	}

	if len(txt) == 0 {
		log.Printf("DNS ERROR", err2)
		return ""
	}

	return txt[0]
}

func getDNS(dns string) (error, string) {
	txt, err2 := net.LookupTXT(dns)
	tryCount := 0

	for tryCount < 4 && err2 != nil {
		time.Sleep(BACKOFF_TIME)
		txt2, err2 := net.LookupTXT(dns)
		if err2 != nil {
			log.Printf("DNS ERROR", err2)
			return err2, ""
		}
		txt = txt2
	}
	if len(txt) == 0 {
		log.Printf("DNS ERROR", err2)
		return err2, ""
	}

	// TODO: Add error handling for when dns looup fails completely

	return nil, txt[0] // we assume the first one is the right one
}

/*
Because months or days may be split between multiple DNS records, we must perform multiple
dns queries per tree node. The below code handles this case, collates it into one string,
and returns the value.
e.g. 202001_0._KeyForge.example.com, 202001_1._KeyForge.example.com
tag = 2020001
all values = 2020001_*._keyforge.example.com

dns = _keyforge.example.com
*/
func getTreeNodeFromDNS(tag, dns string) (error, string) {

	count := 0
	result := ""
	last3 := ""

	for last3 != "EOM" {
		currentDNS := ""
		if tag == "" {
			currentDNS = dns
		} else {
			currentDNS = tag + "_" + strconv.Itoa(count) + "." + dns
		}

		txtEntry := dnsTXTQuery(currentDNS)
		if txtEntry == "" {
			return errors.New("Failed to get DNS:" + currentDNS), ""
		}

		result += txtEntry

		last3 = string(txtEntry[len(txtEntry)-3:])
		count += 1
	}

	return nil, result[:len(result)-len("EOM")]
}

// Provides an entry from a dns cache if it exists, or fetches if it doesn't
func (d *_DNSCache) getPublicFromDNS(key string, treenode string, dns string) (error, string) {
	log.Println("collecting", key, "from node", treenode, " in domain ", dns)

	// Check if the domain is exists:

	domainCache, cached := d.Cache[dns]
	if !cached {
		d.Cache[dns] = make(map[string]map[string]string)
		domainCache = d.Cache[dns]
	}

	_, nodeExists := domainCache[treenode]

	if !nodeExists {

		// get the tree node
		err, nodeData := getTreeNodeFromDNS(treenode, dns)
		if err != nil {
			return err, ""
		}
		domainCache[treenode] = makeTagValueMap(nodeData)
		d.Cache[dns] = domainCache
	}

	return nil, d.Cache[dns][treenode][key]
}

// Gets the Q Values out of DNS for this particular entry
// returns the values along the path e.g. [year, month, day]
func (d *_DNSCache) GetPublicFromDNS(dns string, path []string) (err error, mpk string, public []string) {
	public = make([]string, 0)

	// get public
	err, mpk = d.getPublicFromDNS("public", "", dns)
	if err != nil {
		return
	}

	// year is in the base
	err2, year := d.getPublicFromDNS(path[0], "", dns)
	if err2 != nil {
		return
	}

	// months are in <year key>._keyforge....
	err3, month := d.getPublicFromDNS(path[1], path[0], dns)
	if err3 != nil {
		return
	}

	// Day is in <year><month>.dns
	err4, day := d.getPublicFromDNS(path[2], path[0]+path[1], dns)
	if err4 != nil {
		return
	}

	public = append(public, year)
	public = append(public, month)
	public = append(public, day)

	return
}

func trimQuote(s string) string {
	if last := len(s) - 1; last >= 0 && s[last] == '"' {
		s = s[:last]
	}
	if s[0] == '"' {
		s = s[1:]
	}
	return s
}

// Gets the DNS entry and parses it into int-string variants
func dnsToMap(entry string) (error, map[string]string) {

	err, dnsResult := getDNS(entry)
	if err != nil {
		return err, nil
	}
	return nil, makeTagValueMap(dnsResult)
}

func makeTagValueMap(input string) map[string]string {

	tagged := make(map[string]string)
	values := strings.Split(input, ",")

	for _, value := range values {
		// Should have two entries
		split := strings.SplitN(value, "=", 2)
		key := split[0]
		value := trimQuote(split[1])
		tagged[key] = value
	}
	return tagged

}
