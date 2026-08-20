package live

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// simulated is the fallback capture source. It replays a synthetic but
// realistic home-network trace in real time — genuine Ethernet frames, built
// by the same builders the dissector tests use — so the analyzer is fully
// exercisable on a workstation with no CAP_NET_RAW and no interesting traffic.
//
// It is always labeled as simulated in the UI. Presenting fabricated packets as
// a live capture would be worse than showing nothing.
type simulated struct {
	iface     string
	ch        chan Packet
	done      chan struct{}
	closeOnce sync.Once

	captured atomic.Int64
	bytes    atomic.Int64
	dropped  atomic.Int64
}

type simDevice struct {
	mac    net.HardwareAddr
	ip     net.IP
	name   string
	domain string
	server net.IP
}

// OpenSimulated starts the synthetic source. It never fails.
func OpenSimulated(iface string) Source {
	s := &simulated{
		iface: iface,
		ch:    make(chan Packet, 1024),
		done:  make(chan struct{}),
	}
	go s.loop()
	return s
}

func mac(s string) net.HardwareAddr {
	h, err := net.ParseMAC(s)
	if err != nil {
		panic(fmt.Sprintf("live: bad MAC literal %q in the simulated trace: %v", s, err))
	}
	return h
}

func (s *simulated) loop() {
	defer close(s.ch)

	gateway := mac("02:42:be:ee:00:01")
	devices := []simDevice{
		{mac("3c:84:6a:11:00:02"), net.IPv4(192, 168, 1, 11), "hikvision-cam-01", "ota.hikvision.com", net.IPv4(47, 98, 44, 10)},
		{mac("a4:da:22:bb:00:12"), net.IPv4(192, 168, 1, 21), "samsung-tv", "samsungcloud.tv", net.IPv4(35, 190, 22, 8)},
		{mac("f0:27:2d:dd:00:14"), net.IPv4(192, 168, 1, 30), "macbook-pro", "cdn.apple.com", net.IPv4(104, 16, 20, 5)},
		{mac("b8:27:eb:cc:00:07"), net.IPv4(192, 168, 1, 42), "aqara-lock", "mqtt.tuya.com", net.IPv4(118, 31, 9, 4)},
		{mac("00:11:32:aa:00:33"), net.IPv4(192, 168, 1, 50), "synology-nas", "update.synology.com", net.IPv4(13, 107, 4, 50)},
	}
	resolver := net.IPv4(192, 168, 1, 1)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	var idx int64
	var txid uint16 = 0x1000
	seq := uint32(1000)

	emit := func(frame []byte) {
		idx++
		s.captured.Add(1)
		s.bytes.Add(int64(len(frame)))
		pkt := Packet{
			Index:   idx,
			TS:      time.Now(),
			Iface:   s.iface,
			Data:    frame,
			CapLen:  len(frame),
			OrigLen: len(frame),
		}
		select {
		case s.ch <- pkt:
		case <-s.done:
		default:
			s.dropped.Add(1)
		}
	}

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}

		d := devices[rng.Intn(len(devices))]
		txid++
		seq += uint32(rng.Intn(2000))

		switch rng.Intn(10) {
		case 0, 1: // DNS query then its response — the F21 join, on the wire
			q := BuildDNSQuery(txid, d.domain)
			emit(BuildEthernet(gateway, d.mac, 0x0800,
				BuildIPv4(d.ip, resolver, 17, 64, txid, BuildUDP(uint16(40000+rng.Intn(20000)), 53, q))))

			time.Sleep(15 * time.Millisecond)
			r := BuildDNSResponse(txid, d.domain, []net.IP{d.server}, 300, 0)
			emit(BuildEthernet(d.mac, gateway, 0x0800,
				BuildIPv4(resolver, d.ip, 17, 64, txid+1, BuildUDP(53, uint16(40000+rng.Intn(20000)), r))))

		case 2, 3: // TCP handshake into a TLS ClientHello (F3)
			sport := uint16(49000 + rng.Intn(9000))
			emit(BuildEthernet(gateway, d.mac, 0x0800,
				BuildIPv4(d.ip, d.server, 6, 64, txid, BuildTCP(sport, 443, seq, 0, TCPSyn, nil))))
			emit(BuildEthernet(d.mac, gateway, 0x0800,
				BuildIPv4(d.server, d.ip, 6, 55, txid, BuildTCP(443, sport, 7000, seq+1, TCPSyn|TCPAck, nil))))
			hello := BuildTLSClientHello(d.domain,
				[]string{"h2", "http/1.1"},
				[]uint16{0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030})
			emit(BuildEthernet(gateway, d.mac, 0x0800,
				BuildIPv4(d.ip, d.server, 6, 64, txid+1,
					BuildTCP(sport, 443, seq+1, 7001, TCPPsh|TCPAck, hello))))

		case 4: // plaintext HTTP — still common on IoT firmware update paths
			sport := uint16(49000 + rng.Intn(9000))
			req := fmt.Sprintf("GET /firmware/check?model=%s HTTP/1.1\r\nHost: %s\r\n"+
				"User-Agent: %s/1.4.2\r\nAccept: */*\r\n\r\n", d.name, d.domain, d.name)
			emit(BuildEthernet(gateway, d.mac, 0x0800,
				BuildIPv4(d.ip, d.server, 6, 64, txid,
					BuildTCP(sport, 80, seq, 900, TCPPsh|TCPAck, []byte(req)))))

		case 5: // MQTT CONNECT — the IoT control plane (F4)
			sport := uint16(49000 + rng.Intn(9000))
			emit(BuildEthernet(gateway, d.mac, 0x0800,
				BuildIPv4(d.ip, d.server, 6, 64, txid,
					BuildTCP(sport, 1883, seq, 900, TCPPsh|TCPAck, buildMQTTConnect(d.name)))))

		case 6: // mDNS advertisement — device fingerprinting input (F1)
			q := BuildDNSQuery(0, "_services._dns-sd._udp.local")
			emit(BuildEthernet(mac("01:00:5e:00:00:fb"), d.mac, 0x0800,
				BuildIPv4(d.ip, net.IPv4(224, 0, 0, 251), 17, 255, txid, BuildUDP(5353, 5353, q))))

		case 7: // SSDP discovery (F1)
			body := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
				"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
			emit(BuildEthernet(mac("01:00:5e:7f:ff:fa"), d.mac, 0x0800,
				BuildIPv4(d.ip, net.IPv4(239, 255, 255, 250), 17, 4, txid,
					BuildUDP(uint16(40000+rng.Intn(20000)), 1900, []byte(body)))))

		case 8: // ARP sweep — what lateral movement looks like (F34/F36)
			target := net.IPv4(192, 168, 1, byte(2+rng.Intn(60)))
			emit(BuildEthernet(mac("ff:ff:ff:ff:ff:ff"), d.mac, 0x0806,
				BuildARPRequest(d.mac, d.ip, target)))

		default: // bulk data on an established connection
			sport := uint16(49000 + rng.Intn(9000))
			payload := make([]byte, 200+rng.Intn(1200))
			rng.Read(payload)
			emit(BuildEthernet(gateway, d.mac, 0x0800,
				BuildIPv4(d.ip, d.server, 6, 64, txid,
					BuildTCP(sport, 443, seq, 900, TCPPsh|TCPAck, payload))))
		}
	}
}

// buildMQTTConnect builds a MQTT 3.1.1 CONNECT packet with the given client id.
func buildMQTTConnect(clientID string) []byte {
	var vh []byte
	vh = append(vh, 0, 4, 'M', 'Q', 'T', 'T') // protocol name
	vh = append(vh, 4)                        // protocol level 3.1.1
	vh = append(vh, 0x02)                     // connect flags: clean session
	vh = append(vh, 0, 60)                    // keep-alive 60s
	vh = append(vh, byte(len(clientID)>>8), byte(len(clientID)))
	vh = append(vh, clientID...)
	return append([]byte{0x10, byte(len(vh))}, vh...)
}

func (s *simulated) Name() string           { return "simulator" }
func (s *simulated) Iface() string          { return s.iface }
func (s *simulated) Packets() <-chan Packet { return s.ch }

func (s *simulated) Stats() Stats {
	return Stats{Captured: s.captured.Load(), Dropped: s.dropped.Load(), Bytes: s.bytes.Load()}
}

func (s *simulated) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	return nil
}
