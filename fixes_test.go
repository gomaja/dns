package dns

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestRejectClearsResponseHeaderFlags(t *testing.T) {
	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer func() { _ = s.Shutdown() }()

	cases := []struct {
		name      string
		build     func() []byte
		wantRcode int
	}{
		{
			name: "two_questions_formerr_clears_ra_tc_ad_aa_z",
			build: func() []byte {
				m := new(Msg)
				m.Id = 0x1234
				m.Opcode = OpcodeQuery
				m.Authoritative = true
				m.Truncated = true
				m.RecursionDesired = true
				m.RecursionAvailable = true
				m.Zero = true
				m.AuthenticatedData = true
				m.Question = []Question{
					{Name: "a.example.", Qtype: TypeA, Qclass: ClassINET},
					{Name: "b.example.", Qtype: TypeA, Qclass: ClassINET},
				}
				raw, packErr := m.Pack()
				if packErr != nil {
					t.Fatalf("pack query: %v", packErr)
				}
				return raw
			},
			wantRcode: RcodeFormatError,
		},
		{
			name: "unimplemented_opcode_notimp_clears_ra",
			build: func() []byte {
				m := new(Msg)
				m.Id = 0x2345
				m.Opcode = 15 // unassigned opcode -> MsgRejectNotImplemented
				m.RecursionAvailable = true
				m.Truncated = true
				m.AuthenticatedData = true
				raw, packErr := m.Pack()
				if packErr != nil {
					t.Fatalf("pack query: %v", packErr)
				}
				return raw
			},
			wantRcode: RcodeNotImplemented,
		},
		{
			name: "truncated_question_unpack_formerr_clears_ra",
			build: func() []byte {
				raw := make([]byte, 16)
				binary.BigEndian.PutUint16(raw[0:2], 0x3456)
				// QR=0, Opcode=0, AA=1, TC=1, RD=1, RA=1, Z=1, AD=1, CD=0
				binary.BigEndian.PutUint16(raw[2:4], _AA|_TC|_RD|_RA|_Z|_AD)
				binary.BigEndian.PutUint16(raw[4:6], 1) // QDCOUNT=1, truncated name
				raw[12] = 63                            // claims 63-byte label, only 3 bytes follow
				return raw
			},
			wantRcode: RcodeFormatError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, dialErr := net.DialTimeout("udp", addrstr, time.Second)
			if dialErr != nil {
				t.Fatalf("dial udp: %v", dialErr)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

			if _, writeErr := conn.Write(tc.build()); writeErr != nil {
				t.Fatalf("write: %v", writeErr)
			}
			buf := make([]byte, 512)
			n, readErr := conn.Read(buf)
			if readErr != nil {
				t.Fatalf("read: %v", readErr)
			}
			resp := new(Msg)
			if unpackErr := resp.Unpack(buf[:n]); unpackErr != nil {
				t.Fatalf("unpack: %v", unpackErr)
			}
			if !resp.Response {
				t.Fatalf("expected QR=1")
			}
			if resp.Rcode != tc.wantRcode {
				t.Fatalf("rcode = %d, want %d", resp.Rcode, tc.wantRcode)
			}
			if resp.RecursionAvailable || resp.Authoritative || resp.Truncated || resp.AuthenticatedData || resp.Zero {
				t.Fatalf("unexpected response flags set: RA=%v AA=%v TC=%v AD=%v Z=%v",
					resp.RecursionAvailable, resp.Authoritative, resp.Truncated, resp.AuthenticatedData, resp.Zero)
			}
		})
	}
}

func signXFRMsgWithPrefix(t *testing.T, m *Msg, keyName, secret, priorMAC string, unsignedPrefix []byte, timersOnly bool) ([]byte, string) {
	t.Helper()
	m.SetTsig(keyName, HmacSHA256, 300, time.Now().Unix())
	tsig := m.IsTsig()
	tsig.OrigId = m.Id
	// Strip TSIG from Extra before packing body.
	m.Extra = m.Extra[:len(m.Extra)-1]
	body, err := m.Pack()
	if err != nil {
		t.Fatalf("pack message: %v", err)
	}
	digestInput, err := tsigBufferWithPrefix(unsignedPrefix, body, tsig, priorMAC, timersOnly)
	if err != nil {
		t.Fatalf("tsigBufferWithPrefix: %v", err)
	}
	macBytes, err := tsigHMACProvider(secret).Generate(digestInput, tsig)
	if err != nil {
		t.Fatalf("generate mac: %v", err)
	}
	tsig.MAC = hex.EncodeToString(macBytes)
	tsig.MACSize = uint16(len(macBytes))

	tbuf := make([]byte, 512)
	off, err := PackRR(tsig, tbuf, 0, nil, false)
	if err != nil {
		t.Fatalf("pack tsig: %v", err)
	}
	out := append(body, tbuf[:off]...)
	binary.BigEndian.PutUint16(out[10:], uint16(len(m.Extra)+1))
	return out, tsig.MAC
}

func writeTCPFrame(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(payload)))
	copy(frame[2:], payload)
	if _, err := c.Write(frame); err != nil {
		t.Fatalf("write tcp frame: %v", err)
	}
}

func runCustomAXFRServer(t *testing.T, serve func(c net.Conn, req *Msg, reqMAC string)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		c, accErr := ln.Accept()
		if accErr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		var hdr [2]byte
		if _, readErr := io.ReadFull(c, hdr[:]); readErr != nil {
			return
		}
		buf := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, readErr := io.ReadFull(c, buf); readErr != nil {
			return
		}
		req := new(Msg)
		if unpackErr := req.Unpack(buf); unpackErr != nil {
			return
		}
		var reqMAC string
		if ts := req.IsTsig(); ts != nil {
			reqMAC = ts.MAC
		}
		serve(c, req, reqMAC)
	}()
	return ln.Addr().String()
}

func TestTransferInTSIGUnsignedIntermediatesRFC8945(t *testing.T) {
	const keyName = "axfr-rfc8945."
	const secret = "so6ZGir4GPAqINNh9U5c3A=="

	makeReply := func(req *Msg, rrs ...RR) *Msg {
		m := new(Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Answer = rrs
		return m
	}

	t.Run("accepts_1_unsigned_intermediate", func(t *testing.T) {
		addr := runCustomAXFRServer(t, func(c net.Conn, req *Msg, reqMAC string) {
			raw1, mac1 := signXFRMsgWithPrefix(t, makeReply(req, xfrSoa), keyName, secret, reqMAC, nil, false)
			writeTCPFrame(t, c, raw1)

			raw2, err := makeReply(req, xfrA).Pack()
			if err != nil {
				t.Fatalf("pack msg2: %v", err)
			}
			writeTCPFrame(t, c, raw2)

			raw3, _ := signXFRMsgWithPrefix(t, makeReply(req, xfrMX, xfrSoa), keyName, secret, mac1, raw2, true)
			writeTCPFrame(t, c, raw3)
		})

		tr := &Transfer{TsigSecret: map[string]string{keyName: secret}}
		q := new(Msg)
		q.SetAxfr("miek.nl.")
		q.SetTsig(keyName, HmacSHA256, 300, time.Now().Unix())

		ch, err := tr.In(q, addr)
		if err != nil {
			t.Fatalf("Transfer.In: %v", err)
		}
		var got []RR
		for env := range ch {
			if env.Error != nil {
				t.Fatalf("unexpected envelope error: %v", env.Error)
			}
			got = append(got, env.RR...)
		}
		if len(got) != 4 {
			t.Fatalf("got %d RRs, want 4", len(got))
		}
	})

	t.Run("accepts_99_unsigned_intermediates", func(t *testing.T) {
		addr := runCustomAXFRServer(t, func(c net.Conn, req *Msg, reqMAC string) {
			raw1, mac1 := signXFRMsgWithPrefix(t, makeReply(req, xfrSoa), keyName, secret, reqMAC, nil, false)
			writeTCPFrame(t, c, raw1)

			var prefix []byte
			for i := 0; i < 99; i++ {
				rawMid, err := makeReply(req, xfrA).Pack()
				if err != nil {
					t.Fatalf("pack mid %d: %v", i, err)
				}
				prefix = append(prefix, rawMid...)
				writeTCPFrame(t, c, rawMid)
			}

			rawLast, _ := signXFRMsgWithPrefix(t, makeReply(req, xfrSoa), keyName, secret, mac1, prefix, true)
			writeTCPFrame(t, c, rawLast)
		})

		tr := &Transfer{TsigSecret: map[string]string{keyName: secret}}
		q := new(Msg)
		q.SetAxfr("miek.nl.")
		q.SetTsig(keyName, HmacSHA256, 300, time.Now().Unix())

		ch, err := tr.In(q, addr)
		if err != nil {
			t.Fatalf("Transfer.In: %v", err)
		}
		count := 0
		for env := range ch {
			if env.Error != nil {
				t.Fatalf("unexpected error: %v", env.Error)
			}
			count += len(env.RR)
		}
		if count != 101 {
			t.Fatalf("got %d RRs, want 101", count)
		}
	})

	t.Run("rejects_100_unsigned_intermediates", func(t *testing.T) {
		addr := runCustomAXFRServer(t, func(c net.Conn, req *Msg, reqMAC string) {
			raw1, _ := signXFRMsgWithPrefix(t, makeReply(req, xfrSoa), keyName, secret, reqMAC, nil, false)
			writeTCPFrame(t, c, raw1)
			for i := 0; i < 100; i++ {
				rawMid, _ := makeReply(req, xfrA).Pack()
				frame := make([]byte, 2+len(rawMid))
				binary.BigEndian.PutUint16(frame[0:2], uint16(len(rawMid)))
				copy(frame[2:], rawMid)
				if _, werr := c.Write(frame); werr != nil {
					return
				}
			}
		})

		tr := &Transfer{TsigSecret: map[string]string{keyName: secret}}
		q := new(Msg)
		q.SetAxfr("miek.nl.")
		q.SetTsig(keyName, HmacSHA256, 300, time.Now().Unix())

		ch, err := tr.In(q, addr)
		if err != nil {
			t.Fatalf("Transfer.In: %v", err)
		}
		var gotErr error
		for env := range ch {
			if env.Error != nil {
				gotErr = env.Error
			}
		}
		if !errors.Is(gotErr, ErrNoSig) {
			t.Fatalf("error = %v, want ErrNoSig", gotErr)
		}
	})

	t.Run("rejects_unsigned_first_message", func(t *testing.T) {
		addr := runCustomAXFRServer(t, func(c net.Conn, req *Msg, _ string) {
			raw1, _ := makeReply(req, xfrSoa).Pack()
			writeTCPFrame(t, c, raw1)
		})

		tr := &Transfer{TsigSecret: map[string]string{keyName: secret}}
		q := new(Msg)
		q.SetAxfr("miek.nl.")
		q.SetTsig(keyName, HmacSHA256, 300, time.Now().Unix())

		ch, err := tr.In(q, addr)
		if err != nil {
			t.Fatalf("Transfer.In: %v", err)
		}
		var gotErr error
		for env := range ch {
			if env.Error != nil {
				gotErr = env.Error
			}
		}
		if !errors.Is(gotErr, ErrNoSig) {
			t.Fatalf("error = %v, want ErrNoSig", gotErr)
		}
	})

	t.Run("rejects_unsigned_last_message", func(t *testing.T) {
		addr := runCustomAXFRServer(t, func(c net.Conn, req *Msg, reqMAC string) {
			raw1, _ := signXFRMsgWithPrefix(t, makeReply(req, xfrSoa), keyName, secret, reqMAC, nil, false)
			writeTCPFrame(t, c, raw1)
			rawLast, _ := makeReply(req, xfrSoa).Pack()
			writeTCPFrame(t, c, rawLast)
		})

		tr := &Transfer{TsigSecret: map[string]string{keyName: secret}}
		q := new(Msg)
		q.SetAxfr("miek.nl.")
		q.SetTsig(keyName, HmacSHA256, 300, time.Now().Unix())

		ch, err := tr.In(q, addr)
		if err != nil {
			t.Fatalf("Transfer.In: %v", err)
		}
		var gotErr error
		for env := range ch {
			if env.Error != nil {
				gotErr = env.Error
			}
		}
		if !errors.Is(gotErr, ErrNoSig) {
			t.Fatalf("error = %v, want ErrNoSig", gotErr)
		}
	})

	t.Run("rejects_tampered_unsigned_intermediate", func(t *testing.T) {
		addr := runCustomAXFRServer(t, func(c net.Conn, req *Msg, reqMAC string) {
			raw1, mac1 := signXFRMsgWithPrefix(t, makeReply(req, xfrSoa), keyName, secret, reqMAC, nil, false)
			writeTCPFrame(t, c, raw1)

			raw2Original, _ := makeReply(req, xfrA).Pack()
			raw2Tampered := append([]byte(nil), raw2Original...)
			raw2Tampered[len(raw2Tampered)-1] ^= 0x01 // flip last IP octet
			writeTCPFrame(t, c, raw2Tampered)

			// Signed over untampered raw2Original, so verification against tampered wire bytes MUST fail.
			raw3, _ := signXFRMsgWithPrefix(t, makeReply(req, xfrSoa), keyName, secret, mac1, raw2Original, true)
			writeTCPFrame(t, c, raw3)
		})

		tr := &Transfer{TsigSecret: map[string]string{keyName: secret}}
		q := new(Msg)
		q.SetAxfr("miek.nl.")
		q.SetTsig(keyName, HmacSHA256, 300, time.Now().Unix())

		ch, err := tr.In(q, addr)
		if err != nil {
			t.Fatalf("Transfer.In: %v", err)
		}
		var gotErr error
		for env := range ch {
			if env.Error != nil {
				gotErr = env.Error
			}
		}
		if !errors.Is(gotErr, ErrSig) {
			t.Fatalf("error = %v, want ErrSig", gotErr)
		}
	})
}
