package main

var nullMap map[string]string

type viewDnsStruct struct {
	Query struct {
		Tool string `json:"tool"`
		Host string `json:"host"`
	} `json:"query"`
	Response struct {
		DomainCount string `json:"domain_count"`
		Domains     []struct {
			Name         string `json:"name"`
			LastResolved string `json:"last_resolved"`
		} `json:"domains"`
	} `json:"response"`
}
