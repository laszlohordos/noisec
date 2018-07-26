package noisec_test

import (
	"testing"

	"encoding/hex"
	"fmt"
	"github.com/laszlohordos/noisec"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestNoisec(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Noise-C Suite")
}

var _ = Describe("Noise-C Test", func() {

	It("Parse const bytes", func() {
		var p noisec.NoisePattern
		var d noisec.NoiseDH
		var c noisec.NoiseCipher
		var h noisec.NoiseHash

		Ω(p.Value(0x01)).To(Equal(noisec.NoisePatternN))
		Ω(p).To(Equal(noisec.NoisePatternN))

		Ω(d.Value(0x02)).To(Equal(noisec.NoiseDhCurve448))
		Ω(d).To(Equal(noisec.NoiseDhCurve448))

		Ω(c.Value(0x02)).To(Equal(noisec.NoiseCipherAESGCM))
		Ω(c).To(Equal(noisec.NoiseCipherAESGCM))

		Ω(h.Value(0x02)).To(Equal(noisec.NoiseHashBLAKE2b))
		Ω(h).To(Equal(noisec.NoiseHashBLAKE2b))
	})

	It("Generate X448 KeyPair", func() {
		pub, priv, err := noisec.GenerateX448KeyPair()
		Ω(err).NotTo(HaveOccurred())
		Ω(pub).To(HaveLen(56))
		Ω(priv).To(HaveLen(56))
		fmt.Fprintf(GinkgoWriter, "Pub : %s\n", hex.EncodeToString(pub))
		fmt.Fprintf(GinkgoWriter, "Priv: %s\n", hex.EncodeToString(priv))
		fp, err := noisec.FullFingerprint(pub)
		Ω(err).NotTo(HaveOccurred())
		fmt.Fprintf(GinkgoWriter, "Full fingerprint : %s\n", fp)
		fp, err = noisec.BasicFingerprint(pub)
		Ω(err).NotTo(HaveOccurred())
		fmt.Fprintf(GinkgoWriter, "Basic fingerprint : %s\n", fp)
	})

	It("XK Handshake", func() {
		staticIPub, staticISec, _ := noisec.GenerateX25519KeyPair()
		staticRPub, staticRSec, _ := noisec.GenerateX25519KeyPair()
		var Sremote []byte

		hsI := noisec.HandshakeState{
			Prefix:    noisec.NoisePrefixSTANDARD,
			Pattern:   noisec.NoisePatternXK,
			Dh:        noisec.NoiseDhCurve25519,
			Cipher:    noisec.NoiseCipherCHACHAPOLY,
			Hash:      noisec.NoiseHashBLAKE2s,
			Initiator: true,
		}
		Ω(hsI.Init()).NotTo(HaveOccurred())

		hsR := noisec.HandshakeState{
			Prefix:    noisec.NoisePrefixSTANDARD,
			Pattern:   noisec.NoisePatternXK,
			Dh:        noisec.NoiseDhCurve25519,
			Cipher:    noisec.NoiseCipherCHACHAPOLY,
			Hash:      noisec.NoiseHashBLAKE2s,
			Initiator: false,
		}
		Ω(hsR.Init()).NotTo(HaveOccurred())

		if hsI.NeedsLocalKeyPair() {
			Ω(hsI.SetLocalKeyPair(staticISec)).NotTo(HaveOccurred())
		}
		if hsI.NeedsRemotePublicKey() {
			Ω(hsI.SetRemotePublicKey(staticRPub)).NotTo(HaveOccurred())
		}
		if hsR.NeedsLocalKeyPair() {
			Ω(hsR.SetLocalKeyPair(staticRSec)).NotTo(HaveOccurred())
		}
		if hsR.NeedsRemotePublicKey() {
			Ω(hsR.SetRemotePublicKey(staticIPub)).NotTo(HaveOccurred())
		}

		Ω(hsI.SetPrologue([]byte{0x00, 0x00})).NotTo(HaveOccurred())
		Ω(hsR.SetPrologue([]byte{0x00, 0x00})).NotTo(HaveOccurred())

		Ω(hsI.Start()).NotTo(HaveOccurred())
		Ω(hsR.Start()).NotTo(HaveOccurred())

		msgBuff, resBuff := make([]byte, 1, noisec.NoiseMaxPayloadLen), make([]byte, 1, noisec.NoiseMaxPayloadLen)
		var err error
		var msg, res []byte
		var csI0, csI1, csR0, csR1 *noisec.CipherState

		// -> e, es
		msg, err = hsI.WriteMessage(msgBuff, []byte{0x00, 0x01, 0x02, 0x03})
		Ω(err).NotTo(HaveOccurred())
		Ω(msg).To(HaveLen(52))

		Ω(hsR.GetAction()).To(Equal(noisec.NoiseActionReadMessage))
		res, err = hsR.ReadMessage(resBuff, msg)
		Ω(hsR.GetAction()).To(Equal(noisec.NoiseActionWriteMessage))

		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte{0x00, 0x01, 0x02, 0x03}))

		//<- e, ee
		msg, err = hsR.WriteMessage(nil, []byte{0x08, 0x08, 0x08})
		Ω(err).NotTo(HaveOccurred())
		Ω(msg).To(HaveLen(51))

		res, err = hsI.ReadMessage(nil, msg)
		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte{0x08, 0x08, 0x08}))

		// -> s, se
		msg, err = hsI.WriteMessage(msgBuff, []byte{0x04, 0x05, 0x06, 0x07})
		Ω(err).NotTo(HaveOccurred())
		Ω(msg).To(HaveLen(52 + 16))

		res, err = hsR.ReadMessage(resBuff, msg)
		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte{0x04, 0x05, 0x06, 0x07}))

		Sremote, err = hsR.GetRemotePublicKey()
		Ω(err).NotTo(HaveOccurred())
		fmt.Fprintf(GinkgoWriter, "SRemote pub: %x\n", Sremote)
		//		Ω(Sremote).To(Equal(staticIPub))

		Ω(hsI.GetAction()).To(Equal(noisec.NoiseActionSplit))
		csI0, csI1, err = hsI.Split()
		Ω(hsI.GetAction()).To(Equal(noisec.NoiseActionComplete))
		Ω(err).NotTo(HaveOccurred())
		hsI.Destroy()

		Ω(hsR.GetAction()).To(Equal(noisec.NoiseActionSplit))
		csR0, csR1, err = hsR.Split()
		Ω(hsR.GetAction()).To(Equal(noisec.NoiseActionComplete))
		Ω(err).NotTo(HaveOccurred())
		hsR.Destroy()

		// transport message I -> R again
		msg, err = csI0.Encrypt([]byte("ad"), []byte("secret"))
		Ω(err).NotTo(HaveOccurred())
		res, err = csR1.Decrypt([]byte("ad"), msg)
		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte("secret")))

		// transport message R <- I
		clear := make([]byte, 6, 22)
		copy(clear[0:], []byte("secret"))
		msg, err = csR0.Encrypt(nil, clear)
		res, err = csI1.Decrypt(nil, msg)
		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte("secret")))
		csI0.Destroy()
		csI1.Destroy()
		csR0.Destroy()
		csR1.Destroy()
	})

	It("XX Handshake", func() {
		staticIPub, staticISec, _ := noisec.GenerateX448KeyPair()
		staticRPub, staticRSec, _ := noisec.GenerateX448KeyPair()
		var Sremote []byte
		var err error

		hsI := noisec.HandshakeState{
			Prefix:    noisec.NoisePrefixSTANDARD,
			Pattern:   noisec.NoisePatternXX,
			Dh:        noisec.NoiseDhCurve448,
			Cipher:    noisec.NoiseCipherAESGCM,
			Hash:      noisec.NoiseHashSHA512,
			Initiator: true,
		}
		Ω(hsI.Init()).NotTo(HaveOccurred())

		hsR := noisec.HandshakeState{
			Prefix:    noisec.NoisePrefixSTANDARD,
			Pattern:   noisec.NoisePatternXX,
			Dh:        noisec.NoiseDhCurve448,
			Cipher:    noisec.NoiseCipherAESGCM,
			Hash:      noisec.NoiseHashSHA512,
			Initiator: false,
		}
		Ω(hsR.Init()).NotTo(HaveOccurred())

		if hsI.NeedsLocalKeyPair() {
			Ω(hsI.SetLocalKeyPair(staticISec)).NotTo(HaveOccurred())
		}
		if hsI.NeedsRemotePublicKey() {
			Ω(hsI.SetRemotePublicKey(staticRPub)).NotTo(HaveOccurred())
		}
		if hsR.NeedsLocalKeyPair() {
			Ω(hsR.SetLocalKeyPair(staticRSec)).NotTo(HaveOccurred())
		}
		if hsR.NeedsRemotePublicKey() {
			Ω(hsR.SetRemotePublicKey(staticIPub)).NotTo(HaveOccurred())
		}

		Ω(hsI.SetPrologue([]byte{0x00, 0x00})).NotTo(HaveOccurred())
		Ω(hsR.SetPrologue([]byte{0x00, 0x00})).NotTo(HaveOccurred())

		Ω(hsI.Start()).NotTo(HaveOccurred())
		Ω(hsR.Start()).NotTo(HaveOccurred())

		msgBuff, resBuff := make([]byte, noisec.NoiseMaxPayloadLen), make([]byte, noisec.NoiseMaxPayloadLen)
		var msg, res []byte
		var csI0, csI1, csR0, csR1 *noisec.CipherState

		// -> e
		msg, err = hsI.WriteMessage(msgBuff, []byte("abc"))
		Ω(err).NotTo(HaveOccurred())
		//Ω(msg).To(HaveLen(99))

		res, err = hsR.ReadMessage(resBuff, msg)
		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte("abc")))

		//<- e, ee, s, es
		msg, err = hsR.WriteMessage(msgBuff, []byte("defg"))
		//msg, err = hsR.WriteMessage(msgBuff, nil)
		Ω(err).NotTo(HaveOccurred())
		Ω(msg).To(HaveLen(56 + 16 + 56 + 16 + 4))

		res, err = hsI.ReadMessage(resBuff, msg)
		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte("defg")))

		// -> s, se
		msg, err = hsI.WriteMessage(msgBuff, []byte("hijk"))
		Ω(err).NotTo(HaveOccurred())
		//Ω(msg).To(HaveLen(99))

		res, err = hsR.ReadMessage(resBuff, msg)
		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte("hijk")))

		Sremote, err = hsR.GetRemotePublicKey()
		Ω(err).NotTo(HaveOccurred())
		Ω(Sremote).To(Equal(staticIPub))

		Ω(hsI.GetAction()).To(Equal(noisec.NoiseActionSplit))
		csI0, csI1, err = hsI.Split()
		Ω(err).NotTo(HaveOccurred())
		hsI.Destroy()

		Ω(hsR.GetAction()).To(Equal(noisec.NoiseActionSplit))
		csR0, csR1, err = hsR.Split()
		Ω(err).NotTo(HaveOccurred())
		hsR.Destroy()

		// transport message I -> R again
		msg, err = csI0.Encrypt([]byte("ad"), []byte("secret"))
		Ω(err).NotTo(HaveOccurred())
		res, err = csR1.Decrypt([]byte("ad"), msg)
		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte("secret")))

		// transport message R <- I
		msg, err = csR0.Encrypt(nil, []byte("secret"))
		res, err = csI1.Decrypt(nil, msg)
		Ω(err).NotTo(HaveOccurred())
		Ω(res).To(Equal([]byte("secret")))
		csI0.Destroy()
		csI1.Destroy()
		csR0.Destroy()
		csR1.Destroy()
	})
})
