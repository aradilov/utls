// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

var tests = []handshakeMessage{
	&clientHelloMsg{},
	&serverHelloMsg{},
	&finishedMsg{},

	&certificateMsg{},
	&certificateRequestMsg{},
	&certificateVerifyMsg{
		hasSignatureAlgorithm: true,
	},
	&certificateStatusMsg{},
	&clientKeyExchangeMsg{},
	&newSessionTicketMsg{},
	&encryptedExtensionsMsg{},
	&endOfEarlyDataMsg{},
	&keyUpdateMsg{},
	&newSessionTicketMsgTLS13{},
	&certificateRequestMsgTLS13{},
	&certificateMsgTLS13{},
	&SessionState{},
}

func mustMarshal(t *testing.T, msg handshakeMessage) []byte {
	t.Helper()
	b, err := msg.marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDPIEnrich(t *testing.T) {
	helloMsgBytes, _ := hex.DecodeString("010006ea03031c18b1e1576e8865689a9e6ec12ff4ec1943650c8c19d77183301dc93e2b07062071be8f93b0b3f75fc30a2eb96589bfc2bc8c571d7d1d5abe77e39adff8e6a41a00201a1a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000681ff41002e002c3936326a73755277616c77352f386f2f6d43334c737a422b7950514136476a4d45486f4d4a4c7354664a593d8a8a000044cd00050003026832ff01000100000a000c000aeaea11ec001d00170018002d00020101000500050100000000001b000302000200120000000b000201000010000e000c02683208687474702f312e310017000000000018001600001376662d6964656e742e6d79676172752e636f6dfe0d00ba00000100011500206f28298002ec4e1c8abf8ec4947bf94bdc7d6eda43417cd06ec69faf3ccefa760090444bd6e256cd1e5337327414133aacdddc9430c135a4825bc2e88223f8bc0a5e27b8e30356d17e46b9aaf90b182e6910848cda24e3977ccfe9939ae0593b15329cbc82a389b6a0f94aea3913201655dc9cd93dca6b45dc88b4753131a0775e1d79d1c4e01a13631b6e1afe65d2277b54ae091a04da9e9b805b3c2c663ac7a387226859487aa61f4d0e7356f79b71c0dd000d0012001004030804040105030805050108060601003304ef04edeaea00010011ec04c04956614f5242ed1569490c755cb34d21f1a11643364e30a0d4359c5c3c3f73f24878d3a219e6069c271e5a630a97e769d798a38464c545631f06a71365da9c84d695e8502f00ac2701d1b136aa68ff222df24562ff87947bf4b1d5f88662cc21e5a08044bb428353aecf266daec62cb73b31a76a324dd238535183a8bb0aaf83179d1b453e1bc8d4a2b521e10f81578c92aa74ab72ccdfe8658479098cc210d4d5ac660764c22361932968fe58a456643b5ac6b78ca460ce472cf5f57ba5867e3b228a2a0353c8b5724d4403900c0c4c7a036d8a827dd183e9819797e3bde6907cd9acc0e8d23f5ecc723eb21227295004608c84e86de426310a883c8e375e5a95ca64f318efe9b99de9591e3466d4223ecc27b87f8644ce4b0d91e0a224169bfafa8f6e043ab321a275b742d7295edfd396de387b66a07c15b0862188b8f6272a7c429438e045e2ec0eb517c5615a01a502b4461bcbe2e75976535cb4177dbf259e3112131eb35cae4c6afaa60111eb43fec234277a5b4f5c34dcab9e27835a9535794d79b08cfab464c087cd5aca5f495e7bf9001672b95645be7f7b8ad27637cef40578145fe1199afa2a4d428634b9d0c2128468fc194f5a2c2139acbe29bc365c5589c86b4635f33b8df94166c65e2750262a3b6e17117c83f14b53c21857e68d4cac5bc30cc506581d403880a2e00758154baa6c6553037a1ed9052fa46df58a50bde322e66162fd532fc5f20b29799040b40e9adc63d67556c161c94995b50a737cbbf40d90b05949674000575df91b001cba2705c97e461829155373b6319417531001912366458d662b4c0fdc6b001617bfdab084e5927954bb5c08396e57863a6ca4fad4c971192433a57f22d05b982277022819fe47c517f32bc5bba9d58ac71ef08edf7329c20966bcb643ee39b19c21809fc78c57ccb69fbc8828757dd73caeedb0710e05402db4c332aca7c1b610104c35391445673195366c8c3c610e1b42c6b597a58ed5a230718c9e048df8322854babc6ef67ca0a30d0b717836718228b7087eb8b5a5f92586f97e90092ae1c12e7067bb1d272f6ee7907478984c02415c4a7b1f42833d0992e59427755bca44a86f00f192ecc86b652cadbf448ecbdc15f3157759958f289078c74441cb0a8f0067a6e83243299b24eea4ab10e20ab7d98167245220160869228d420029885a0887e016afac33875870d35894321bbf26938fe8294301406151b699526c9fb9622da677749d229cbe929200083f175722368399b4fba4031695a6422d18ab4430cbb3adf3565f207da2d7c3b713b56626c7c98abb86648799e2199f738db82221a5972d0c56ace4ac91a76c53cadb7a561b250b8a12429081247cbff78905fcaab26ab824a8845567a78c367b2ad0454f1da771e4d4b0c8001b0d2070418a1b33cb5ad1b4b8a2391084ba1c302b1f14a04f2d5cb803193856c8b98ce3a532ea8971194556a9107b310567aa352e2c4e0d6517030c2b8a1888f968302d3931375681ce75ae5071c5ca1376fe246cc72a32e41c88c2917ac517ae028c8b4a722e8a065b4da2816d38ae6ca991bde9af944761a63203d7389dad37b630335bf96057acb43d28d7b1117c08c76eb587c877417d81c3dd7ca8920abe3a09fcc9db41b291f8941f440645dc5b003698534caf670149f05a5da99854dadc5525fef030784fe43cf27200b73306001d00205d116d8e17d8bfaac090bdf47d81ee5f7b11617f7fb9099c46f2b73d17b0bf4800230000002b0007063a3a030403035a5a000100")
	if len(helloMsgBytes) != 1774 {
		t.Errorf("expected raw data length 1774, got %d", len(helloMsgBytes))
	}

	m := clientHelloMsg{
		dpiEnrich: map[uint16]uint64{65345: 0, 27: 0},
	}

	if !m.unmarshal(helloMsgBytes) {
		t.Fatalf("unmarshal failed")
	}

	for extension, extmeta := range m.dpiEnrich {
		var offset uint32 = uint32(extmeta >> 32)
		var extlen uint32 = uint32(extmeta & 0xffffffff)
		switch extension {
		case 65345:
			if extlen != 46 {
				t.Fatalf("expected extlen = 46, got %d", extlen)
			}

			if !bytes.Equal(m.extractedExtensionsData[offset:offset+extlen], []byte("\x00,962jsuRwalw5/8o/mC3LszB+yPQA6GjMEHoMJLsTfJY=")) {
				t.Fatalf("unexpected data for extension 65345, got %q", m.extractedExtensionsData[offset:offset+extlen])
			}
		}

	}
}

func TestMarshalUnmarshal(t *testing.T) {
	rand := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i, m := range tests {
		ty := reflect.ValueOf(m).Type()
		t.Run(ty.String(), func(t *testing.T) {
			n := 100
			if testing.Short() {
				n = 5
			}
			for j := 0; j < n; j++ {
				v, ok := quick.Value(ty, rand)
				if !ok {
					t.Errorf("#%d: failed to create value", i)
					break
				}

				m1 := v.Interface().(handshakeMessage)
				marshaled := mustMarshal(t, m1)
				if !m.unmarshal(marshaled) {
					t.Errorf("#%d failed to unmarshal %#v %x", i, m1, marshaled)
					break
				}

				if m, ok := m.(*SessionState); ok {
					m.activeCertHandles = nil
				}

				if ch, ok := m.(*clientHelloMsg); ok {
					// extensions is special cased, as it is only populated by the
					// server-side of a handshake and is not expected to roundtrip
					// through marshal + unmarshal.  m ends up with the list of
					// extensions necessary to serialize the other fields of
					// clientHelloMsg, so check that it is non-empty, then clear it.
					if len(ch.extensions) == 0 {
						t.Errorf("expected ch.extensions to be populated on unmarshal")
					}
					ch.extensions = nil
				}

				// clientHelloMsg and serverHelloMsg, when unmarshalled, store
				// their original representation, for later use in the handshake
				// transcript. In order to prevent DeepEqual from failing since
				// we didn't create the original message via unmarshalling, nil
				// the field.
				switch t := m.(type) {
				case *clientHelloMsg:
					t.original = nil
				case *serverHelloMsg:
					t.original = nil
				case *certificateRequestMsgTLS13: // [UTLS]
					t.original = nil // [UTLS]
				}

				if !reflect.DeepEqual(m1, m) {
					t.Errorf("#%d got:%#v want:%#v %x", i, m, m1, marshaled)
					break
				}

				if i >= 3 {
					// The first three message types (ClientHello,
					// ServerHello and Finished) are allowed to
					// have parsable prefixes because the extension
					// data is optional and the length of the
					// Finished varies across versions.
					for j := 0; j < len(marshaled); j++ {
						if m.unmarshal(marshaled[0:j]) {
							t.Errorf("#%d unmarshaled a prefix of length %d of %#v", i, j, m1)
							break
						}
					}
				}
			}
		})
	}
}

func TestFuzz(t *testing.T) {
	rand := rand.New(rand.NewSource(0))
	for _, m := range tests {
		for j := 0; j < 1000; j++ {
			len := rand.Intn(1000)
			bytes := randomBytes(len, rand)
			// This just looks for crashes due to bounds errors etc.
			m.unmarshal(bytes)
		}
	}
}

func randomBytes(n int, rand *rand.Rand) []byte {
	r := make([]byte, n)
	if _, err := rand.Read(r); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	return r
}

func randomString(n int, rand *rand.Rand) string {
	b := randomBytes(n, rand)
	return string(b)
}

func (*clientHelloMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &clientHelloMsg{}
	m.vers = uint16(rand.Intn(65536))
	m.random = randomBytes(32, rand)
	m.sessionId = randomBytes(rand.Intn(32), rand)
	m.cipherSuites = make([]uint16, rand.Intn(63)+1)
	for i := 0; i < len(m.cipherSuites); i++ {
		cs := uint16(rand.Int31())
		if cs == scsvRenegotiation {
			cs += 1
		}
		m.cipherSuites[i] = cs
	}
	m.compressionMethods = randomBytes(rand.Intn(63)+1, rand)
	if rand.Intn(10) > 5 {
		m.serverName = randomString(rand.Intn(255), rand)
		for strings.HasSuffix(m.serverName, ".") {
			m.serverName = m.serverName[:len(m.serverName)-1]
		}
	}
	m.ocspStapling = rand.Intn(10) > 5
	m.supportedPoints = randomBytes(rand.Intn(5)+1, rand)
	m.supportedCurves = make([]CurveID, rand.Intn(5)+1)
	for i := range m.supportedCurves {
		m.supportedCurves[i] = CurveID(rand.Intn(30000) + 1)
	}
	if rand.Intn(10) > 5 {
		m.ticketSupported = true
		if rand.Intn(10) > 5 {
			m.sessionTicket = randomBytes(rand.Intn(300), rand)
		} else {
			m.sessionTicket = make([]byte, 0)
		}
	}
	if rand.Intn(10) > 5 {
		m.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
	}
	if rand.Intn(10) > 5 {
		m.supportedSignatureAlgorithmsCert = supportedSignatureAlgorithms()
	}
	for i := 0; i < rand.Intn(5); i++ {
		m.alpnProtocols = append(m.alpnProtocols, randomString(rand.Intn(20)+1, rand))
	}
	if rand.Intn(10) > 5 {
		m.scts = true
	}
	if rand.Intn(10) > 5 {
		m.secureRenegotiationSupported = true
		m.secureRenegotiation = randomBytes(rand.Intn(50)+1, rand)
	}
	if rand.Intn(10) > 5 {
		m.extendedMasterSecret = true
	}
	for i := 0; i < rand.Intn(5); i++ {
		m.supportedVersions = append(m.supportedVersions, uint16(rand.Intn(0xffff)+1))
	}
	if rand.Intn(10) > 5 {
		m.cookie = randomBytes(rand.Intn(500)+1, rand)
	}
	for i := 0; i < rand.Intn(5); i++ {
		var ks keyShare
		ks.group = CurveID(rand.Intn(30000) + 1)
		ks.data = randomBytes(rand.Intn(200)+1, rand)
		m.keyShares = append(m.keyShares, ks)
	}
	switch rand.Intn(3) {
	case 1:
		m.pskModes = []uint8{pskModeDHE}
	case 2:
		m.pskModes = []uint8{pskModeDHE, pskModePlain}
	}
	for i := 0; i < rand.Intn(5); i++ {
		var psk pskIdentity
		psk.obfuscatedTicketAge = uint32(rand.Intn(500000))
		psk.label = randomBytes(rand.Intn(500)+1, rand)
		m.pskIdentities = append(m.pskIdentities, psk)
		m.pskBinders = append(m.pskBinders, randomBytes(rand.Intn(50)+32, rand))
	}
	if rand.Intn(10) > 5 {
		m.quicTransportParameters = randomBytes(rand.Intn(500), rand)
	}
	if rand.Intn(10) > 5 {
		m.earlyData = true
	}
	if rand.Intn(10) > 5 {
		m.encryptedClientHello = randomBytes(rand.Intn(50)+1, rand)
	}

	return reflect.ValueOf(m)
}

func (*serverHelloMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &serverHelloMsg{}
	m.vers = uint16(rand.Intn(65536))
	m.random = randomBytes(32, rand)
	m.sessionId = randomBytes(rand.Intn(32), rand)
	m.cipherSuite = uint16(rand.Int31())
	m.compressionMethod = uint8(rand.Intn(256))
	m.supportedPoints = randomBytes(rand.Intn(5)+1, rand)

	if rand.Intn(10) > 5 {
		m.ocspStapling = true
	}
	if rand.Intn(10) > 5 {
		m.ticketSupported = true
	}
	if rand.Intn(10) > 5 {
		m.alpnProtocol = randomString(rand.Intn(32)+1, rand)
	}

	for i := 0; i < rand.Intn(4); i++ {
		m.scts = append(m.scts, randomBytes(rand.Intn(500)+1, rand))
	}

	if rand.Intn(10) > 5 {
		m.secureRenegotiationSupported = true
		m.secureRenegotiation = randomBytes(rand.Intn(50)+1, rand)
	}
	if rand.Intn(10) > 5 {
		m.extendedMasterSecret = true
	}
	if rand.Intn(10) > 5 {
		m.supportedVersion = uint16(rand.Intn(0xffff) + 1)
	}
	if rand.Intn(10) > 5 {
		m.cookie = randomBytes(rand.Intn(500)+1, rand)
	}
	if rand.Intn(10) > 5 {
		for i := 0; i < rand.Intn(5); i++ {
			m.serverShare.group = CurveID(rand.Intn(30000) + 1)
			m.serverShare.data = randomBytes(rand.Intn(200)+1, rand)
		}
	} else if rand.Intn(10) > 5 {
		m.selectedGroup = CurveID(rand.Intn(30000) + 1)
	}
	if rand.Intn(10) > 5 {
		m.selectedIdentityPresent = true
		m.selectedIdentity = uint16(rand.Intn(0xffff))
	}
	if rand.Intn(10) > 5 {
		m.encryptedClientHello = randomBytes(rand.Intn(50)+1, rand)
	}
	if rand.Intn(10) > 5 {
		m.serverNameAck = rand.Intn(2) == 1
	}

	return reflect.ValueOf(m)
}

func (*encryptedExtensionsMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &encryptedExtensionsMsg{}

	if rand.Intn(10) > 5 {
		m.alpnProtocol = randomString(rand.Intn(32)+1, rand)
	}
	if rand.Intn(10) > 5 {
		m.earlyData = true
	}

	return reflect.ValueOf(m)
}

func (*certificateMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &certificateMsg{}
	numCerts := rand.Intn(20)
	m.certificates = make([][]byte, numCerts)
	for i := 0; i < numCerts; i++ {
		m.certificates[i] = randomBytes(rand.Intn(10)+1, rand)
	}
	return reflect.ValueOf(m)
}

func (*certificateRequestMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &certificateRequestMsg{}
	m.certificateTypes = randomBytes(rand.Intn(5)+1, rand)
	for i := 0; i < rand.Intn(100); i++ {
		m.certificateAuthorities = append(m.certificateAuthorities, randomBytes(rand.Intn(15)+1, rand))
	}
	return reflect.ValueOf(m)
}

func (*certificateVerifyMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &certificateVerifyMsg{}
	m.hasSignatureAlgorithm = true
	m.signatureAlgorithm = SignatureScheme(rand.Intn(30000))
	m.signature = randomBytes(rand.Intn(15)+1, rand)
	return reflect.ValueOf(m)
}

func (*certificateStatusMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &certificateStatusMsg{}
	m.response = randomBytes(rand.Intn(10)+1, rand)
	return reflect.ValueOf(m)
}

func (*clientKeyExchangeMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &clientKeyExchangeMsg{}
	m.ciphertext = randomBytes(rand.Intn(1000)+1, rand)
	return reflect.ValueOf(m)
}

func (*finishedMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &finishedMsg{}
	m.verifyData = randomBytes(12, rand)
	return reflect.ValueOf(m)
}

func (*newSessionTicketMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &newSessionTicketMsg{}
	m.ticket = randomBytes(rand.Intn(4), rand)
	return reflect.ValueOf(m)
}

var sessionTestCerts []*x509.Certificate

func init() {
	cert, err := x509.ParseCertificate(testRSACertificate)
	if err != nil {
		panic(err)
	}
	sessionTestCerts = append(sessionTestCerts, cert)
	cert, err = x509.ParseCertificate(testRSACertificateIssuer)
	if err != nil {
		panic(err)
	}
	sessionTestCerts = append(sessionTestCerts, cert)
}

func (*SessionState) Generate(rand *rand.Rand, size int) reflect.Value {
	s := &SessionState{}
	isTLS13 := rand.Intn(10) > 5
	if isTLS13 {
		s.version = VersionTLS13
	} else {
		s.version = uint16(rand.Intn(VersionTLS13))
	}
	s.isClient = rand.Intn(10) > 5
	s.cipherSuite = uint16(rand.Intn(math.MaxUint16))
	s.createdAt = uint64(rand.Int63())
	s.secret = randomBytes(rand.Intn(100)+1, rand)
	for n, i := rand.Intn(3), 0; i < n; i++ {
		s.Extra = append(s.Extra, randomBytes(rand.Intn(100), rand))
	}
	if rand.Intn(10) > 5 {
		s.EarlyData = true
	}
	if rand.Intn(10) > 5 {
		s.extMasterSecret = true
	}
	if s.isClient || rand.Intn(10) > 5 {
		if rand.Intn(10) > 5 {
			s.peerCertificates = sessionTestCerts
		} else {
			s.peerCertificates = sessionTestCerts[:1]
		}
	}
	if rand.Intn(10) > 5 && s.peerCertificates != nil {
		s.ocspResponse = randomBytes(rand.Intn(100)+1, rand)
	}
	if rand.Intn(10) > 5 && s.peerCertificates != nil {
		for i := 0; i < rand.Intn(2)+1; i++ {
			s.scts = append(s.scts, randomBytes(rand.Intn(500)+1, rand))
		}
	}
	if len(s.peerCertificates) > 0 {
		for i := 0; i < rand.Intn(3); i++ {
			if rand.Intn(10) > 5 {
				s.verifiedChains = append(s.verifiedChains, s.peerCertificates)
			} else {
				s.verifiedChains = append(s.verifiedChains, s.peerCertificates[:1])
			}
		}
	}
	if rand.Intn(10) > 5 && s.EarlyData {
		s.alpnProtocol = string(randomBytes(rand.Intn(10), rand))
	}
	if s.isClient {
		if isTLS13 {
			s.useBy = uint64(rand.Int63())
			s.ageAdd = uint32(rand.Int63() & math.MaxUint32)
		}
	}
	return reflect.ValueOf(s)
}

func (s *SessionState) marshal() ([]byte, error) { return s.Bytes() }
func (s *SessionState) unmarshal(b []byte) bool {
	ss, err := ParseSessionState(b)
	if err != nil {
		return false
	}
	*s = *ss
	return true
}

func (*endOfEarlyDataMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &endOfEarlyDataMsg{}
	return reflect.ValueOf(m)
}

func (*keyUpdateMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &keyUpdateMsg{}
	m.updateRequested = rand.Intn(10) > 5
	return reflect.ValueOf(m)
}

func (*newSessionTicketMsgTLS13) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &newSessionTicketMsgTLS13{}
	m.lifetime = uint32(rand.Intn(500000))
	m.ageAdd = uint32(rand.Intn(500000))
	m.nonce = randomBytes(rand.Intn(100), rand)
	m.label = randomBytes(rand.Intn(1000), rand)
	if rand.Intn(10) > 5 {
		m.maxEarlyData = uint32(rand.Intn(500000))
	}
	return reflect.ValueOf(m)
}

func (*certificateRequestMsgTLS13) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &certificateRequestMsgTLS13{}
	if rand.Intn(10) > 5 {
		m.ocspStapling = true
	}
	if rand.Intn(10) > 5 {
		m.scts = true
	}
	if rand.Intn(10) > 5 {
		m.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
	}
	if rand.Intn(10) > 5 {
		m.supportedSignatureAlgorithmsCert = supportedSignatureAlgorithms()
	}
	if rand.Intn(10) > 5 {
		m.certificateAuthorities = make([][]byte, 3)
		for i := 0; i < 3; i++ {
			m.certificateAuthorities[i] = randomBytes(rand.Intn(10)+1, rand)
		}
	}
	return reflect.ValueOf(m)
}

func (*certificateMsgTLS13) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &certificateMsgTLS13{}
	for i := 0; i < rand.Intn(2)+1; i++ {
		m.certificate.Certificate = append(
			m.certificate.Certificate, randomBytes(rand.Intn(500)+1, rand))
	}
	if rand.Intn(10) > 5 {
		m.ocspStapling = true
		m.certificate.OCSPStaple = randomBytes(rand.Intn(100)+1, rand)
	}
	if rand.Intn(10) > 5 {
		m.scts = true
		for i := 0; i < rand.Intn(2)+1; i++ {
			m.certificate.SignedCertificateTimestamps = append(
				m.certificate.SignedCertificateTimestamps, randomBytes(rand.Intn(500)+1, rand))
		}
	}
	return reflect.ValueOf(m)
}

// [UTLS]
func (*utlsCompressedCertificateMsg) Generate(rand *rand.Rand, size int) reflect.Value {
	m := &utlsCompressedCertificateMsg{}
	m.algorithm = uint16(rand.Intn(2 << 15))
	m.uncompressedLength = uint32(rand.Intn(2 << 23))
	m.compressedCertificateMessage = randomBytes(rand.Intn(500)+1, rand)
	return reflect.ValueOf(m)
}

func TestRejectEmptySCTList(t *testing.T) {
	// RFC 6962, Section 3.3.1 specifies that empty SCT lists are invalid.

	var random [32]byte
	sct := []byte{0x42, 0x42, 0x42, 0x42}
	serverHello := &serverHelloMsg{
		vers:   VersionTLS12,
		random: random[:],
		scts:   [][]byte{sct},
	}
	serverHelloBytes := mustMarshal(t, serverHello)

	var serverHelloCopy serverHelloMsg
	if !serverHelloCopy.unmarshal(serverHelloBytes) {
		t.Fatal("Failed to unmarshal initial message")
	}

	// Change serverHelloBytes so that the SCT list is empty
	i := bytes.Index(serverHelloBytes, sct)
	if i < 0 {
		t.Fatal("Cannot find SCT in ServerHello")
	}

	var serverHelloEmptySCT []byte
	serverHelloEmptySCT = append(serverHelloEmptySCT, serverHelloBytes[:i-6]...)
	// Append the extension length and SCT list length for an empty list.
	serverHelloEmptySCT = append(serverHelloEmptySCT, []byte{0, 2, 0, 0}...)
	serverHelloEmptySCT = append(serverHelloEmptySCT, serverHelloBytes[i+4:]...)

	// Update the handshake message length.
	serverHelloEmptySCT[1] = byte((len(serverHelloEmptySCT) - 4) >> 16)
	serverHelloEmptySCT[2] = byte((len(serverHelloEmptySCT) - 4) >> 8)
	serverHelloEmptySCT[3] = byte(len(serverHelloEmptySCT) - 4)

	// Update the extensions length
	serverHelloEmptySCT[42] = byte((len(serverHelloEmptySCT) - 44) >> 8)
	serverHelloEmptySCT[43] = byte((len(serverHelloEmptySCT) - 44))

	if serverHelloCopy.unmarshal(serverHelloEmptySCT) {
		t.Fatal("Unmarshaled ServerHello with empty SCT list")
	}
}

func TestRejectEmptySCT(t *testing.T) {
	// Not only must the SCT list be non-empty, but the SCT elements must
	// not be zero length.

	var random [32]byte
	serverHello := &serverHelloMsg{
		vers:   VersionTLS12,
		random: random[:],
		scts:   [][]byte{nil},
	}
	serverHelloBytes := mustMarshal(t, serverHello)

	var serverHelloCopy serverHelloMsg
	if serverHelloCopy.unmarshal(serverHelloBytes) {
		t.Fatal("Unmarshaled ServerHello with zero-length SCT")
	}
}

func TestRejectDuplicateExtensions(t *testing.T) {
	clientHelloBytes, err := hex.DecodeString("010000440303000000000000000000000000000000000000000000000000000000000000000000000000001c0000000a000800000568656c6c6f0000000a000800000568656c6c6f")
	if err != nil {
		t.Fatalf("failed to decode test ClientHello: %s", err)
	}
	var clientHelloCopy clientHelloMsg
	if clientHelloCopy.unmarshal(clientHelloBytes) {
		t.Error("Unmarshaled ClientHello with duplicate extensions")
	}

	serverHelloBytes, err := hex.DecodeString("02000030030300000000000000000000000000000000000000000000000000000000000000000000000000080005000000050000")
	if err != nil {
		t.Fatalf("failed to decode test ServerHello: %s", err)
	}
	var serverHelloCopy serverHelloMsg
	if serverHelloCopy.unmarshal(serverHelloBytes) {
		t.Fatal("Unmarshaled ServerHello with duplicate extensions")
	}
}
