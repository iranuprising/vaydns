// vaydns-client is the client end of a DNS tunnel.
package vaydnsclient

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"vaydns-go/client"
	"vaydns-go/noise"
	"vaydns-go/turbotunnel"
	log "github.com/sirupsen/logrus"
)

var version = "dev"

func RunVayDNS(pubkeyStr, domainStr, localAddrStr, remoteResolverStr, utlsFingerprint string, compatDnstt bool, cancelCtx context.Context, ready chan<- string) error {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05"})

	var dohURL string
	var dotAddr string
	var udpAddr string

	if strings.HasPrefix(remoteResolverStr, "https://") {
		dohURL = remoteResolverStr
	} else if strings.Contains(remoteResolverStr, ":853") {
		dotAddr = remoteResolverStr
	} else {
		udpAddr = remoteResolverStr
		if !strings.Contains(udpAddr, ":") {
			udpAddr += ":53"
		}
	}

	// Default values from original main.go
	utlsDistribution := utlsFingerprint
	if utlsDistribution == "" {
		utlsDistribution = "4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13"
	}

	maxQnameLen := 101
	maxNumLabels := 0
	rpsLimit := 0.0
	idleTimeoutStr := client.DefaultIdleTimeout.String()
	keepAliveStr := client.DefaultKeepAlive.String()
	reconnectMinStr := client.DefaultReconnectDelay.String()
	reconnectMaxStr := client.DefaultReconnectMaxDelay.String()
	sessionCheckIntervalStr := client.DefaultSessionCheckInterval.String()
	openStreamTimeoutStr := client.DefaultOpenStreamTimeout.String()
	maxStreams := client.DefaultMaxStreams
	udpWorkers := client.DefaultUDPWorkers
	udpSharedSocket := false
	udpTimeoutStr := client.DefaultUDPResponseTimeout.String()
	udpAcceptErrors := false
	clientIDSize := 2
	recordTypeStr := "txt"
	queueSize := turbotunnel.QueueSize
	kcpWindowSize := 0
	queueOverflowStr := string(turbotunnel.DefaultQueueOverflowMode)

	// Apply -vaydns-compat overrides EXACTLY like original main.go
	if compatDnstt {
		recordTypeStr = "txt"
		maxQnameLen = 253
		idleTimeoutStr = client.DnsttIdleTimeout.String()
		keepAliveStr = client.DnsttKeepAlive.String()
	}

	// Parse durations
	idleTimeout, _ := time.ParseDuration(idleTimeoutStr)
	keepAlive, _ := time.ParseDuration(keepAliveStr)
	reconnectMinDelay, _ := time.ParseDuration(reconnectMinStr)
	reconnectMaxDelay, _ := time.ParseDuration(reconnectMaxStr)
	sessionCheckInterval, _ := time.ParseDuration(sessionCheckIntervalStr)
	openStreamTimeout, _ := time.ParseDuration(openStreamTimeoutStr)
	udpTimeout, _ := time.ParseDuration(udpTimeoutStr)
	queueOverflowMode, _ := turbotunnel.ParseQueueOverflowMode(queueOverflowStr)

	if kcpWindowSize == 0 {
		kcpWindowSize = queueSize / 2
		if kcpWindowSize < 1 {
			kcpWindowSize = 1
		}
	}

	// Resolve public key
	pubkeyHex, err := DecodeKey(pubkeyStr)
	if err != nil {
		return fmt.Errorf("invalid pubkey: %v", err)
	}

	// Select uTLS fingerprint
	utlsClientHelloID, err := client.SampleUTLSDistribution(utlsDistribution)
	if err != nil {
		return fmt.Errorf("parsing -utls: %v", err)
	}

	// Select resolver transport
	var resolverType client.ResolverType
	var resolverAddr string
	if dohURL != "" {
		resolverType = client.ResolverTypeDOH
		resolverAddr = dohURL
	} else if dotAddr != "" {
		resolverType = client.ResolverTypeDOT
		resolverAddr = dotAddr
	} else if udpAddr != "" {
		resolverType = client.ResolverTypeUDP
		resolverAddr = udpAddr
	}

	// Build resolver
	resolver, err := client.NewResolver(resolverType, resolverAddr)
	if err != nil {
		return fmt.Errorf("resolver: %v", err)
	}
	resolver.UTLSClientHelloID = utlsClientHelloID
	resolver.UDPWorkers = udpWorkers
	resolver.UDPSharedSocket = udpSharedSocket
	resolver.UDPTimeout = udpTimeout
	resolver.UDPAcceptErrors = udpAcceptErrors

	// Build tunnel server config
	ts, err := client.NewTunnelServer(domainStr, hex.EncodeToString(pubkeyHex))
	if err != nil {
		return err
	}
	ts.DnsttCompat = compatDnstt
	ts.ClientIDSize = clientIDSize
	ts.MaxQnameLen = maxQnameLen
	ts.MaxNumLabels = maxNumLabels
	ts.RPS = rpsLimit
	ts.RecordType = recordTypeStr

	// Build tunnel
	tunnel, err := client.NewTunnel(resolver, ts)
	if err != nil {
		return err
	}
	tunnel.IdleTimeout = idleTimeout
	tunnel.KeepAlive = keepAlive
	tunnel.OpenStreamTimeout = openStreamTimeout
	tunnel.MaxStreams = maxStreams
	tunnel.ReconnectMinDelay = reconnectMinDelay
	tunnel.ReconnectMaxDelay = reconnectMaxDelay
	tunnel.SessionCheckInterval = sessionCheckInterval
	tunnel.PacketQueueSize = queueSize
	tunnel.KCPWindowSize = kcpWindowSize
	tunnel.QueueOverflowMode = queueOverflowMode
	tunnel.Context = cancelCtx

	if ready != nil {
		tunnel.ReadyCallback = func(addr string) {
			select {
			case ready <- addr:
			default:
			}
		}
	}

	log.Infof("VayDNS starting: domain=%s local=%s resolver=%s type=%s compat=%v", domainStr, localAddrStr, remoteResolverStr, resolverType, compatDnstt)

	// Listen
	ln, err := net.Listen("tcp", localAddrStr)
	if err != nil {
		return err
	}

	go func() {
		<-cancelCtx.Done()
		ln.Close()
	}()

	return tunnel.Serve(ln)
}

func DecodeKey(s string) ([]byte, error) {
	return noise.DecodeKey(s)
}

func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}
