package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
)

const (
	forwardDNS    = "10.10.10.1:53"
	mdnsDomain    = "zwift.local"
	localhostAddr = "127.0.0.1"
)

var (
	zwiftServerAddr = localhostAddr
	zwiftFakeDomain = []string{
		"us-or-rly101.zwift.com",
		"secure.zwift.com",
		"cdn.zwift.com",
		"launcher.zwift.com",
	}
)

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		queryDomainName := q.Name[:len(q.Name)-1]
		isZwiftFakeDomain := false
		for _, domain := range zwiftFakeDomain {
			if domain == queryDomainName {
				isZwiftFakeDomain = true
				log.Println("zwift query", q.String())
			}
		}
		if isZwiftFakeDomain {
			ip, err := resolveMDNS(mdnsDomain)
			if err != nil {
				log.Printf("mDNS 解析失败: %v", err)
				dns.HandleFailed(w, r)
				return
			}

			if q.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				msg.Answer = append(msg.Answer, rr)
			}
		} else {
			resp, err := forwardQuery(r)
			if err != nil {
				log.Printf("DNS 透传失败: %v", err)
				dns.HandleFailed(w, r)
				return
			}
			w.WriteMsg(resp)
			return
		}
	}

	w.WriteMsg(&msg)
}

func forwardQuery(req *dns.Msg) (*dns.Msg, error) {
	client := new(dns.Client)
	resp, _, err := client.Exchange(req, forwardDNS)
	return resp, err
}

func resolveMDNS(hostname string) (string, error) {
	if zwiftServerAddr == localhostAddr {
		return "", errors.ErrUnsupported
	}
	return zwiftServerAddr, nil
}

func doMDNSResolve() {
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
			zwiftServerAddr = src.String()
		} else {
			log.Println(src, answer, err)
		}
		time.Sleep(time.Second * 5)
	}
}

func main() {
	server := &dns.Server{Addr: ":53", Net: "udp"}
	dns.HandleFunc(".", handleDNSRequest)
	go doMDNSResolve()

	fmt.Println("DNS 服务器运行在 53 端口...")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DNS 服务器启动失败: %v", err)
	}
}
