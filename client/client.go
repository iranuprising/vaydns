// Package client provides a reusable DNS tunnel client library.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"vaydns-go/dns"
	"vaydns-go/noise"
	"vaydns-go/turbotunnel"
	utls "github.com/refraction-networking/utls"
	log "github.com/sirupsen/logrus"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// Default timeouts for VayDNS mode.
const (
	DefaultIdleTimeout          = 10 * time.Second
	DefaultKeepAlive            = 2 * time.Second
	DefaultOpenStreamTimeout    = 10 * time.Second
	DefaultReconnectDelay       = 1 * time.Second
	DefaultReconnectMaxDelay    = 30 * time.Second
	DefaultSessionCheckInterval = 500 * time.Millisecond
	DefaultUDPResponseTimeout   = 500 * time.Millisecond
	DefaultUDPWorkers           = 100
	DefaultMaxStreams           = 0 // unlimited
	DefaultHandshakeTimeout     = 15 * time.Second
)

// Default timeouts for dnstt compatibility mode.
const (
	DnsttIdleTimeout = 2 * time.Minute
	DnsttKeepAlive   = 10 * time.Second
)

// ResolverType identifies the DNS transport to use.
type ResolverType string

const (
	ResolverTypeUDP ResolverType = "udp"
	ResolverTypeDOT ResolverType = "dot"
	ResolverTypeDOH ResolverType = "doh"
)

// Resolver holds DNS resolver configuration.
type Resolver struct {
	ResolverType ResolverType
	ResolverAddr string

	UTLSClientHelloID *utls.ClientHelloID
	RoundTripper      http.RoundTripper
	DialerControl     func(network, address string, c syscall.RawConn) error

	UDPWorkers      int
	UDPSharedSocket bool
	UDPTimeout      time.Duration
	UDPAcceptErrors bool
}

func NewResolver(resolverType ResolverType, resolverAddr string) (Resolver, error) {
	switch resolverType {
	case ResolverTypeUDP, ResolverTypeDOT, ResolverTypeDOH:
	default:
		return Resolver{}, fmt.Errorf("unsupported resolver type: %s", resolverType)
	}
	return Resolver{
		ResolverType: resolverType,
		ResolverAddr: resolverAddr,
	}, nil
}

type TunnelServer struct {
	Addr               dns.Name
	PubKey             string
	MTU                int
	decodedNoisePubKey []byte
	DnsttCompat        bool
	ClientIDSize       int
	MaxQnameLen        int
	MaxNumLabels       int
	RPS                float64
	RecordType         string
}

func NewTunnelServer(addr string, pubKeyString string) (TunnelServer, error) {
	domain, err := dns.ParseName(addr)
	if err != nil {
		return TunnelServer{}, fmt.Errorf("invalid domain %+q: %w", addr, err)
	}
	pubkey, err := noise.DecodeKey(pubKeyString)
	if err != nil {
		return TunnelServer{}, fmt.Errorf("pubkey format error: %w", err)
	}
	return TunnelServer{
		Addr:               domain,
		PubKey:             pubKeyString,
		decodedNoisePubKey: pubkey,
	}, nil
}

func (ts *TunnelServer) wireConfig() turbotunnel.WireConfig {
	if ts.DnsttCompat {
		return turbotunnel.WireConfig{ClientIDSize: 8, Compat: true}
	}
	size := ts.ClientIDSize
	if size <= 0 {
		size = 2
	}
	return turbotunnel.WireConfig{ClientIDSize: size}
}

func (ts *TunnelServer) effectiveRRType() uint16 {
	rt, err := dns.ParseRecordType(ts.RecordType)
	if err != nil {
		return dns.RRTypeTXT
	}
	return rt
}

func (ts *TunnelServer) effectiveMaxQnameLen() int {
	if ts.MaxQnameLen > 0 {
		return ts.MaxQnameLen
	}
	if ts.DnsttCompat {
		return 253
	}
	return 101
}

type Tunnel struct {
	Resolver     Resolver
	TunnelServer TunnelServer
	Context      context.Context

	IdleTimeout          time.Duration
	KeepAlive            time.Duration
	OpenStreamTimeout    time.Duration
	MaxStreams           int
	ReconnectMinDelay    time.Duration
	ReconnectMaxDelay    time.Duration
	SessionCheckInterval time.Duration
	HandshakeTimeout     time.Duration
	PacketQueueSize      int
	KCPWindowSize        int
	QueueOverflowMode    turbotunnel.QueueOverflowMode
	ReadyCallback        func(string)

	wireConfig    turbotunnel.WireConfig
	forgedStats   *ForgedStats
	resolverConn  net.PacketConn
	dnsPacketConn *DNSPacketConn
	kcpConn       *kcp.UDPSession
	noiseChannel  io.ReadWriteCloser
	smuxSession   *smux.Session
	remoteAddr    net.Addr
	connWG        sync.WaitGroup
}

func NewTunnel(resolver Resolver, tunnelServer TunnelServer) (*Tunnel, error) {
	t := &Tunnel{
		Resolver:     resolver,
		TunnelServer: tunnelServer,
	}
	t.wireConfig = tunnelServer.wireConfig()
	return t, nil
}

func (t *Tunnel) applyDefaults() {
	isDnstt := t.TunnelServer.DnsttCompat
	if t.IdleTimeout == 0 {
		if isDnstt {
			t.IdleTimeout = DnsttIdleTimeout
		} else {
			t.IdleTimeout = DefaultIdleTimeout
		}
	}
	if t.KeepAlive == 0 {
		if isDnstt {
			t.KeepAlive = DnsttKeepAlive
		} else {
			t.KeepAlive = DefaultKeepAlive
		}
	}
	if t.OpenStreamTimeout == 0 { t.OpenStreamTimeout = DefaultOpenStreamTimeout }
	if t.MaxStreams == 0 { t.MaxStreams = DefaultMaxStreams }
	if t.ReconnectMinDelay == 0 { t.ReconnectMinDelay = DefaultReconnectDelay }
	if t.ReconnectMaxDelay == 0 { t.ReconnectMaxDelay = DefaultReconnectMaxDelay }
	if t.SessionCheckInterval == 0 { t.SessionCheckInterval = DefaultSessionCheckInterval }
	if t.HandshakeTimeout == 0 { t.HandshakeTimeout = DefaultHandshakeTimeout }
	if t.Context == nil { t.Context = context.Background() }
}

func (t *Tunnel) effectivePacketQueueSize() int {
	if t.PacketQueueSize > 0 { return t.PacketQueueSize }
	return turbotunnel.QueueSize
}

func (t *Tunnel) effectiveQueueOverflowMode() turbotunnel.QueueOverflowMode {
	if t.QueueOverflowMode != "" { return t.QueueOverflowMode }
	return turbotunnel.DefaultQueueOverflowMode
}

func (t *Tunnel) effectiveKCPWindowSize() int {
	if t.KCPWindowSize > 0 { return t.KCPWindowSize }
	ws := t.effectivePacketQueueSize() / 2
	if ws < 1 { ws = 1 }
	return ws
}

func (t *Tunnel) InitiateResolverConnection() error {
	r := t.Resolver
	switch r.ResolverType {
	case ResolverTypeUDP:
		addr, err := net.ResolveUDPAddr("udp", r.ResolverAddr)
		if err != nil { return err }
		t.remoteAddr = addr
		if r.UDPSharedSocket {
			lc := net.ListenConfig{Control: r.DialerControl}
			conn, err := lc.ListenPacket(context.Background(), "udp", ":0")
			if err != nil { return err }
			t.resolverConn = conn
		} else {
			workers := r.UDPWorkers
			if workers <= 0 { workers = DefaultUDPWorkers }
			timeout := r.UDPTimeout
			if timeout <= 0 { timeout = DefaultUDPResponseTimeout }
			conn, forgedStats, err := NewUDPPacketConn(addr, r.DialerControl, workers, timeout, !r.UDPAcceptErrors, t.effectivePacketQueueSize(), t.effectiveQueueOverflowMode())
			if err != nil { return err }
			t.forgedStats = forgedStats
			t.resolverConn = conn
		}
		return nil
	case ResolverTypeDOH:
		t.remoteAddr = turbotunnel.DummyAddr{}
		var rt http.RoundTripper
		if r.RoundTripper != nil { rt = r.RoundTripper } else if r.UTLSClientHelloID != nil {
			rt = NewUTLSRoundTripper(nil, r.UTLSClientHelloID)
		} else { rt = http.DefaultTransport }
		conn, err := NewHTTPPacketConn(rt, r.ResolverAddr, 8, t.effectivePacketQueueSize(), t.effectiveQueueOverflowMode())
		if err != nil { return err }
		t.resolverConn = conn
		return nil
	case ResolverTypeDOT:
		t.remoteAddr = turbotunnel.DummyAddr{}
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if r.UTLSClientHelloID != nil {
			id := r.UTLSClientHelloID
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return UTLSDialContext(ctx, network, addr, nil, id)
			}
		} else {
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tls.DialWithDialer(&net.Dialer{}, network, addr, nil)
			}
		}
		conn, err := NewTLSPacketConn(r.ResolverAddr, dialTLSContext, t.effectivePacketQueueSize(), t.effectiveQueueOverflowMode())
		if err != nil { return err }
		t.resolverConn = conn
		return nil
	default:
		return fmt.Errorf("unsupported resolver type: %s", r.ResolverType)
	}
}

func (t *Tunnel) InitiateDNSPacketConn(domain dns.Name) error {
	var rateLimiter *RateLimiter
	if t.TunnelServer.RPS > 0 { rateLimiter = NewRateLimiter(t.TunnelServer.RPS) }
	maxQnameLen := t.TunnelServer.effectiveMaxQnameLen()
	rrType := t.TunnelServer.effectiveRRType()
	t.dnsPacketConn = NewDNSPacketConn(t.resolverConn, t.remoteAddr, domain, rateLimiter, maxQnameLen, t.TunnelServer.MaxNumLabels, t.wireConfig, t.forgedStats, rrType, t.effectivePacketQueueSize(), t.effectiveQueueOverflowMode())
	return nil
}

func (t *Tunnel) InitiateKCPConn(mtu int) error {
	if mtu <= 0 {
		maxQnameLen := t.TunnelServer.effectiveMaxQnameLen()
		mtu = DNSNameCapacity(t.TunnelServer.Addr, maxQnameLen, t.TunnelServer.MaxNumLabels) - t.wireConfig.DataOverhead()
	}
	if mtu < 25 {
		return fmt.Errorf("MTU %d is too small (minimum 25)", mtu)
	}
	t.TunnelServer.MTU = mtu
	log.Infof("effective MTU %d", mtu)
	conn, err := kcp.NewConn2(t.remoteAddr, nil, 0, 0, t.dnsPacketConn)
	if err != nil { return fmt.Errorf("opening KCP conn: %v", err) }
	log.Infof("session %08x ready", conn.GetConv())
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(t.effectiveKCPWindowSize(), t.effectiveKCPWindowSize())
	if rc := conn.SetMtu(mtu); !rc {
		conn.Close()
		return fmt.Errorf("failed to set KCP MTU to %d", mtu)
	}
	t.kcpConn = conn
	return nil
}

func (t *Tunnel) InitiateNoiseChannel() error {
	t.applyDefaults()
	rw, err := noiseHandshake(t.kcpConn, t.TunnelServer.decodedNoisePubKey, t.HandshakeTimeout)
	if err != nil { return err }
	t.noiseChannel = rw
	return nil
}

func noiseHandshake(conn *kcp.UDPSession, pubkey []byte, timeout time.Duration) (io.ReadWriteCloser, error) {
	type result struct {
		rw  io.ReadWriteCloser
		err error
	}
	ch := make(chan result, 1)
	go func() {
		rw, err := noise.NewClient(conn, pubkey)
		ch <- result{rw, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		if res.err != nil { return nil, fmt.Errorf("noise handshake: %v", res.err) }
		return res.rw, nil
	case <-timer.C:
		return nil, fmt.Errorf("noise handshake: timeout")
	}
}

func (t *Tunnel) InitiateSmuxSession() error {
	t.applyDefaults()
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = t.KeepAlive
	smuxConfig.KeepAliveTimeout = t.IdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(t.noiseChannel, smuxConfig)
	if err != nil { return fmt.Errorf("opening smux session: %v", err) }
	t.smuxSession = sess
	return nil
}

func openStreamWithTimeout(conv uint32, timeout time.Duration, open func() (*smux.Stream, error)) (*smux.Stream, error) {
	type result struct {
		stream *smux.Stream
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := open()
		ch <- result{s, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil { return nil, fmt.Errorf("session %08x opening stream: %v", conv, r.err) }
		return r.stream, nil
	case <-timer.C:
		go func() { if r, ok := <-ch; ok && r.stream != nil { r.stream.Close() } }()
		return nil, fmt.Errorf("session %08x opening stream: timed out after %v", conv, timeout)
	}
}

func shouldLogCopyError(err error) bool {
	if err == nil || err == io.EOF || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) { return false }
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() { return false }
	return true
}

func (t *Tunnel) OpenStream() (net.Conn, error) {
	if t.smuxSession == nil { return nil, fmt.Errorf("smux session is not initialized") }
	timeout := t.OpenStreamTimeout
	if timeout <= 0 { timeout = DefaultOpenStreamTimeout }
	var conv uint32
	if t.kcpConn != nil { conv = t.kcpConn.GetConv() }
	stream, err := openStreamWithTimeout(conv, timeout, t.smuxSession.OpenStream)
	if err != nil { return nil, err }
	log.Debugf("stream %08x:%d ready", conv, stream.ID())
	return stream, nil
}

func (t *Tunnel) Handle(lconn *net.TCPConn) error {
	stream, err := t.OpenStream()
	if err != nil { return err }
	defer stream.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, lconn)
		if shouldLogCopyError(err) { log.Warnf("copy stream←local: %v", err) }
		lconn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(lconn, stream)
		if shouldLogCopyError(err) { log.Warnf("copy local←stream: %v", err) }
		lconn.CloseWrite()
		lconn.CloseRead()
	}()
	wg.Wait()
	return nil
}

func (t *Tunnel) Close() error {
	if t.smuxSession != nil { t.smuxSession.Close(); t.smuxSession = nil }
	if t.noiseChannel != nil { t.noiseChannel.Close(); t.noiseChannel = nil }
	if t.kcpConn != nil { log.Debugf("session %08x closed", t.kcpConn.GetConv()); t.kcpConn.Close(); t.kcpConn = nil }
	t.closeTransportLayers()
	return nil
}

func (t *Tunnel) closeTransportLayers() {
	if t.dnsPacketConn != nil { t.dnsPacketConn.Close(); t.dnsPacketConn = nil }
	if t.resolverConn != nil { t.resolverConn.Close(); t.resolverConn = nil }
	t.forgedStats = nil
}

func (t *Tunnel) resetTransportLayers() error {
	t.closeTransportLayers()
	if err := t.InitiateResolverConnection(); err != nil { return fmt.Errorf("resolver connection: %w", err) }
	if err := t.InitiateDNSPacketConn(t.TunnelServer.Addr); err != nil {
		t.closeTransportLayers()
		return fmt.Errorf("DNS packet conn: %w", err)
	}
	return nil
}

func (t *Tunnel) ListenAndServe(listenAddr string) error {
	t.applyDefaults()
	localAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil { return fmt.Errorf("invalid listen address: %v", err) }
	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil { return fmt.Errorf("opening local listener: %v", err) }
	log.Infof("listening on %s", ln.Addr())
	return t.Serve(ln)
}

func (t *Tunnel) Serve(ln net.Listener) error {
	t.applyDefaults()
	defer ln.Close()
	defer t.closeTransportLayers()
	defer t.connWG.Wait()

	maxQnameLen := t.TunnelServer.effectiveMaxQnameLen()
	mtu := DNSNameCapacity(t.TunnelServer.Addr, maxQnameLen, t.TunnelServer.MaxNumLabels) - t.wireConfig.DataOverhead()
	if mtu < 25 { return fmt.Errorf("MTU %d too small", mtu) }
	log.Infof("effective MTU %d", mtu)

	var sem chan struct{}
	if t.MaxStreams > 0 { sem = make(chan struct{}, t.MaxStreams) }

	for {
		select {
		case <-t.Context.Done(): return t.Context.Err()
		default:
		}

		var transportErrCh <-chan error
		delay := t.ReconnectMinDelay
		for {
			select {
			case <-t.Context.Done(): return t.Context.Err()
			default:
			}
			if err := t.resetTransportLayers(); err != nil {
				log.Warnf("rebuild failed: %v; retry in %v", err, delay)
				select {
				case <-t.Context.Done(): return t.Context.Err()
				case <-time.After(delay):
				}
				delay *= 2
				if delay > t.ReconnectMaxDelay { delay = t.ReconnectMaxDelay }
				continue
			}
			transportErrCh = t.dnsPacketConn.TransportErrors()
			break
		}

		var conn *kcp.UDPSession
		var sess *smux.Session
		var err error
		delay = t.ReconnectMinDelay
		for {
			select {
			case <-t.Context.Done(): return t.Context.Err()
			default:
			}
			conn, sess, err = t.createSession(mtu)
			if err == nil { break }
			log.Warnf("creation failed: %v; retry in %v", err, delay)
			select {
			case <-t.Context.Done(): return t.Context.Err()
			case <-time.After(delay):
			}
			delay *= 2
			if delay > t.ReconnectMaxDelay { delay = t.ReconnectMaxDelay }
		}

		if t.ReadyCallback != nil {
			t.ReadyCallback(ln.Addr().String())
			t.ReadyCallback = nil
		}

		sessDone := sess.CloseChan()
		conv := conn.GetConv()
		tcpln, _ := ln.(*net.TCPListener)
		sessionAlive := true
		for sessionAlive {
			select {
			case <-t.Context.Done():
				sess.Close(); conn.Close(); t.closeTransportLayers()
				return t.Context.Err()
			default:
			}

			if tcpln != nil { tcpln.SetDeadline(time.Now().Add(100 * time.Millisecond)) }
			local, err := ln.Accept()
			if tcpln != nil { tcpln.SetDeadline(time.Time{}) }
			if err != nil {
				if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
					select {
					case <-sessDone: sessionAlive = false; continue
					case <-t.Context.Done(): sessionAlive = false; continue
					case tErr := <-transportErrCh:
						log.Warnf("session %08x transport error: %v", conv, tErr)
						sessionAlive = false; continue
					default: continue
					}
				}
				sess.Close(); conn.Close(); t.closeTransportLayers()
				return err
			}

			go func(sess *smux.Session, conv uint32) {
				t.connWG.Add(1)
				defer t.connWG.Done()
				if sem != nil {
					sem <- struct{}{}
					defer func() { <-sem }()
				}
				defer local.Close()
				err := t.handleConn(local.(*net.TCPConn), sess, conv)
				if err != nil { log.Warnf("handle: %v", err) }
			}(sess, conv)
		}
		sess.Close(); conn.Close(); t.closeTransportLayers()
	}
}

func (t *Tunnel) createSession(mtu int) (*kcp.UDPSession, *smux.Session, error) {
	conn, err := kcp.NewConn2(t.remoteAddr, nil, 0, 0, t.dnsPacketConn)
	if err != nil { return nil, nil, fmt.Errorf("opening KCP conn: %v", err) }
	log.Infof("session %08x ready", conn.GetConv())
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(t.effectiveKCPWindowSize(), t.effectiveKCPWindowSize())
	if rc := conn.SetMtu(mtu); !rc {
		conn.Close()
		return nil, nil, fmt.Errorf("failed to set KCP MTU to %d", mtu)
	}
	rw, err := noiseHandshake(conn, t.TunnelServer.decodedNoisePubKey, t.HandshakeTimeout)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = t.KeepAlive
	smuxConfig.KeepAliveTimeout = t.IdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("opening smux session: %v", err)
	}
	return conn, sess, nil
}

func (t *Tunnel) handleConn(local *net.TCPConn, sess *smux.Session, conv uint32) error {
	stream, err := openStreamWithTimeout(conv, t.OpenStreamTimeout, sess.OpenStream)
	if err != nil { return err }
	defer func() { log.Debugf("stream %08x:%d closed", conv, stream.ID()); stream.Close() }()
	log.Infof("stream %08x:%d ready", conv, stream.ID())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if shouldLogCopyError(err) { log.Warnf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err) }
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if shouldLogCopyError(err) { log.Warnf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err) }
		local.CloseWrite()
		local.CloseRead()
	}()
	wg.Wait()
	return nil
}

func DNSNameCapacity(domain dns.Name, maxQnameLen int, maxNumLabels int) int {
	const labelLen = 63
	if maxQnameLen <= 0 || maxQnameLen > 253 { maxQnameLen = 253 }
	domainWireLen := 0
	for _, label := range domain { domainWireLen += 1 + len(label) }
	availableWireBytes := maxQnameLen - domainWireLen
	if availableWireBytes <= 0 { return 0 }
	encodedCapacity := availableWireBytes * labelLen / (labelLen + 1)
	if maxNumLabels > 0 {
		maxEncoded := maxNumLabels * labelLen
		if encodedCapacity > maxEncoded { encodedCapacity = maxEncoded }
	}
	rawCapacity := encodedCapacity * 5 / 8
	return rawCapacity
}

func SampleUTLSDistribution(spec string) (*utls.ClientHelloID, error) {
	weights, labels, err := parseWeightedList(spec)
	if err != nil { return nil, err }
	ids := make([]*utls.ClientHelloID, 0, len(labels))
	for _, label := range labels {
		var id *utls.ClientHelloID
		if label == "none" { id = nil } else {
			id = UTLSLookup(label)
			if id == nil { return nil, fmt.Errorf("unknown TLS fingerprint %q", label) }
		}
		ids = append(ids, id)
	}
	return ids[sampleWeighted(weights)], nil
}

func UTLSClientHelloIDMap() []struct { Label string; ID *utls.ClientHelloID } { return utlsClientHelloIDMap }

type Outbound struct {
	Resolvers     []Resolver
	TunnelServers []TunnelServer
	tunnels       []*Tunnel
}

func NewOutbound(resolvers []Resolver, tunnelServers []TunnelServer) *Outbound {
	return &Outbound{
		Resolvers:     resolvers,
		TunnelServers: tunnelServers,
	}
}

func (o *Outbound) Start(bind string) error {
	resolver := o.Resolvers[0]
	tunnelServer := o.TunnelServers[0]
	tunnel, err := NewTunnel(resolver, tunnelServer)
	if err != nil { return fmt.Errorf("failed to create tunnel: %w", err) }
	o.tunnels = []*Tunnel{tunnel}
	return tunnel.ListenAndServe(bind)
}
