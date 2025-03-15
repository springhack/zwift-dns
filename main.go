package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
)

const (
	mdnsDomain        = "zwift.local"
	upstreamDnsServer = "10.10.10.1:53"
)

var (
	mu            sync.RWMutex
	currentIP     = net.ParseIP("127.0.0.1")
	targetDomains = []string{
		"us-or-rly101.zwift.com.",
		"secure.zwift.com.",
		"cdn.zwift.com.",
		"launcher.zwift.com.",
	}
)

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	var finalQuestion []dns.Question
	var finalAnswer []dns.RR

	finalResponse := &dns.Msg{}
	finalResponse.SetReply(r)
	finalResponse.Authoritative = true
	finalResponse.Question = r.Question[:]

	for _, question := range r.Question {
		switch question.Qtype {
		case dns.TypeA:
			if slices.Contains(targetDomains, strings.ToLower(question.Name)) && currentIP != nil {
				mu.Lock()
				// fake a type a answer
				rr, _ := dns.NewRR(fmt.Sprintf("%s A %s", question.Name, currentIP))
				mu.Unlock()
				rr.Header().Ttl = 300
				finalAnswer = append(finalAnswer, rr)
			} else {
				// forward to upstream if not match
				finalQuestion = append(finalQuestion, question)
			}
		case dns.TypeAAAA:
			if !slices.Contains(targetDomains, strings.ToLower(question.Name)) {
				// forward type aaaa question if not match
				finalQuestion = append(finalQuestion, question)
			}
			continue
		default:
			// forward to upstream
			finalQuestion = append(finalQuestion, question)
		}
	}

	log.Println("Q:", finalQuestion, finalAnswer)
	// forward other questions and combine it's answers into finalAnswer
	if len(finalQuestion) != 0 {
		r.Question = finalQuestion
		response := forwardRequest(r)
		if response != nil {
			finalAnswer = append(finalAnswer, response.Answer...)
			log.Println("O:", response.Answer)
		}
	}

	log.Println("F:", finalAnswer)
	// write response
	finalResponse.Answer = append(finalResponse.Answer, finalAnswer...)
	w.WriteMsg(finalResponse)
}

func forwardRequest(r *dns.Msg) *dns.Msg {
	client := new(dns.Client)
	resp, _, err := client.Exchange(r, upstreamDnsServer)
	if err != nil {
		log.Printf("Failed to forward DNS request: %v", err)
		return nil
	}
	return resp
}

func updateMDNSRecords() {
	addr4, err := net.ResolveUDPAddr("udp4", mdns.DefaultAddressIPv4)
	if err != nil {
		panic(err)
	}

	l4, err := net.ListenUDP("udp4", addr4)
	if err != nil {
		panic(err)
	}

	packetConnV4 := ipv4.NewPacketConn(l4)
	server, err := mdns.Server(packetConnV4, nil, &mdns.Config{})
	if err != nil {
		panic(err)
	}

	for {
		answer, src, err := server.QueryAddr(context.TODO(), mdnsDomain)
		if err == nil {
			srcSlice := src.As4()
			mu.Lock()
			currentIP = net.IP(srcSlice[:])
			mu.Unlock()
		} else {
			log.Println("Find mdns ip faied:", src, answer, err)
		}
		time.Sleep(time.Second * 5)
	}
}

func main() {
	go updateMDNSRecords()

	dns.HandleFunc(".", handleDNSRequest)
	server := &dns.Server{Addr: ":53", Net: "udp"}

	log.Println("Starting DNS server on :53")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
}
