package noisec

// #cgo pkg-config: noise-c
// #include <noise/protocol.h>
// #include <string.h>
//
//int generate_key(int curve_id, uint8_t *priv_key, size_t priv_key_len, uint8_t *pub_key, size_t pub_key_len )
//{
//    NoiseDHState *dh;
//    int err;
//
//    /* Generate a keypair */
//    err = noise_dhstate_new_by_id(&dh, curve_id);
//    if (err != NOISE_ERROR_NONE) {
//        return err;
//    }
//    err = noise_dhstate_generate_keypair(dh);
//    if (err != NOISE_ERROR_NONE) {
//        /* Clean up */
//        noise_dhstate_free(dh);
//        return err;
//    }
//    err = noise_dhstate_get_keypair(dh, priv_key, priv_key_len, pub_key, pub_key_len);
//
//    /* Clean up */
//    noise_dhstate_free(dh);
//    return err;
//}
//
//int create_handshake(NoiseHandshakeState **handshake, int role, int prefix_id, int pattern_id, int dh_id, int cipher_id, int hash_id) {
//    NoiseProtocolId nid;
//    int err;
//
//    memset(&nid, 0, sizeof(NoiseProtocolId));
//    nid.prefix_id = prefix_id;
//    nid.pattern_id = pattern_id;
//    nid.dh_id = dh_id;
//    nid.cipher_id = cipher_id;
//    nid.hash_id = hash_id;
//
//    err = noise_handshakestate_new_by_id(handshake, &nid, role);
//    if (err != NOISE_ERROR_NONE) {
//        noise_free(&nid, sizeof(NoiseProtocolId));
//        return err;
//    }
//    return NOISE_ERROR_NONE;
//}
//
//int write_handshake(NoiseHandshakeState *handshake, uint8_t *data, size_t *data_size, uint8_t *payload, size_t payload_size) {
//    NoiseBuffer mbuf;
//    NoiseBuffer pbuf;
//    int err;
//
//    if (payload) {
//        noise_buffer_set_output(mbuf, data, *data_size);
//        noise_buffer_set_input(pbuf, payload, payload_size);
//        err = noise_handshakestate_write_message(handshake, &mbuf, &pbuf);
//    } else {
//        noise_buffer_set_output(mbuf, data, *data_size);
//        err = noise_handshakestate_write_message(handshake, &mbuf, NULL);
//    }
//    if (err != NOISE_ERROR_NONE) {
//        return err;
//    }
//    *data_size = mbuf.size;
//    return NOISE_ERROR_NONE;
//}
//
//int read_handshake(NoiseHandshakeState *handshake, uint8_t *data, size_t data_size, uint8_t *payload, size_t *payload_max_size) {
//    NoiseBuffer mbuf;
//    NoiseBuffer pbuf;
//    int err;
//
//    noise_buffer_set_input(mbuf, data, data_size);
//    noise_buffer_set_output(pbuf, payload, *payload_max_size);
//    err = noise_handshakestate_read_message(handshake, &mbuf, &pbuf);
//
//    if (err != NOISE_ERROR_NONE) {
//        return err;
//    }
//    *payload_max_size = pbuf.size;
//    return NOISE_ERROR_NONE;
//}
//
//int cipherstate_encrypt_with_ad(NoiseCipherState *state, const uint8_t *ad, size_t ad_len, uint8_t *data, size_t *data_size, size_t data_max_size) {
//    NoiseBuffer buffer;
//    int err;
//
//    noise_buffer_set_inout(buffer, data, *data_size, data_max_size);
//    err = noise_cipherstate_encrypt_with_ad(state, ad, ad_len, &buffer);
//    if (err != NOISE_ERROR_NONE) {
//        return err;
//    }
//    *data_size = buffer.size;
//    return NOISE_ERROR_NONE;
//}
//
//int cipherstate_decrypt_with_ad(NoiseCipherState *state, const uint8_t *ad, size_t ad_len, uint8_t *data, size_t *data_size, size_t data_max_size) {
//    NoiseBuffer buffer;
//    int err;
//
//    noise_buffer_set_inout(buffer, data, *data_size, data_max_size);
//    err = noise_cipherstate_decrypt_with_ad(state, ad, ad_len, &buffer);
//    if (err != NOISE_ERROR_NONE) {
//        return err;
//    }
//    *data_size = buffer.size;
//    return NOISE_ERROR_NONE;
//}
//
import "C"
import (
	"fmt"
	"github.com/pkg/errors"
	"unsafe"
)

func Init() {
	result := C.noise_init()
	if result != C.NOISE_ERROR_NONE {
		panic(fmt.Sprintf("Noise-C initialization failed, result code %d.", int(result)))
	}
}

type (
	NoiseCipher    uint16
	NoiseHash      uint16
	NoiseDH        uint16
	NoisePattern   uint16
	NoisePrefix    uint16
	NoiseSign      uint16
	NoiseAction    uint16
	HandshakeState struct {
		Prefix NoisePrefix
		// Pattern is the pattern for the handshake.
		Pattern NoisePattern
		Dh      NoiseDH
		Cipher  NoiseCipher
		Hash    NoiseHash

		// Initiator must be true if the first message in the handshake will be sent
		// by this peer.
		Initiator bool

		handshakeState *C.struct_NoiseHandshakeState_s
	}
	CipherState struct {
		cipherState *C.struct_NoiseCipherState_s
	}
)

const (
	/* AEAD cipher algorithms */
	NoiseCipherNone       = NoiseCipher(C.NOISE_CIPHER_NONE)
	NoiseCipherCategory   = NoiseCipher(C.NOISE_CIPHER_CATEGORY)
	NoiseCipherCHACHAPOLY = NoiseCipher(C.NOISE_CIPHER_CHACHAPOLY)
	NoiseCipherAESGCM     = NoiseCipher(C.NOISE_CIPHER_AESGCM)

	/* Hash algorithms */
	NoiseHashNONE     = NoiseHash(C.NOISE_HASH_NONE)
	NoiseHashCATEGORY = NoiseHash(C.NOISE_HASH_CATEGORY)
	NoiseHashBLAKE2s  = NoiseHash(C.NOISE_HASH_BLAKE2s)
	NoiseHashBLAKE2b  = NoiseHash(C.NOISE_HASH_BLAKE2b)
	NoiseHashSHA256   = NoiseHash(C.NOISE_HASH_SHA256)
	NoiseHashSHA512   = NoiseHash(C.NOISE_HASH_SHA512)

	/* Diffie-Hellman algorithms */
	NoiseDhNONE       = NoiseDH(C.NOISE_DH_NONE)
	NoiseDhCATEGORY   = NoiseDH(C.NOISE_DH_CATEGORY)
	NoiseDhCurve25519 = NoiseDH(C.NOISE_DH_CURVE25519)
	NoiseDhCurve448   = NoiseDH(C.NOISE_DH_CURVE448)
	NoiseDhNewHope    = NoiseDH(C.NOISE_DH_NEWHOPE)

	/* Handshake patterns */
	NoisePatternNONE       = NoisePattern(C.NOISE_PATTERN_NONE)
	NoisePatternCATEGORY   = NoisePattern(C.NOISE_PATTERN_CATEGORY)
	NoisePatternN          = NoisePattern(C.NOISE_PATTERN_N)
	NoisePatternX          = NoisePattern(C.NOISE_PATTERN_X)
	NoisePatternK          = NoisePattern(C.NOISE_PATTERN_K)
	NoisePatternNN         = NoisePattern(C.NOISE_PATTERN_NN)
	NoisePatternNK         = NoisePattern(C.NOISE_PATTERN_NK)
	NoisePatternNX         = NoisePattern(C.NOISE_PATTERN_NX)
	NoisePatternXN         = NoisePattern(C.NOISE_PATTERN_XN)
	NoisePatternXK         = NoisePattern(C.NOISE_PATTERN_XK)
	NoisePatternXX         = NoisePattern(C.NOISE_PATTERN_XX)
	NoisePatternKN         = NoisePattern(C.NOISE_PATTERN_KN)
	NoisePatternKK         = NoisePattern(C.NOISE_PATTERN_KK)
	NoisePatternKX         = NoisePattern(C.NOISE_PATTERN_KX)
	NoisePatternIN         = NoisePattern(C.NOISE_PATTERN_IN)
	NoisePatternIK         = NoisePattern(C.NOISE_PATTERN_IK)
	NoisePatternIX         = NoisePattern(C.NOISE_PATTERN_IX)
	NoisePatternXXFallback = NoisePattern(C.NOISE_PATTERN_XX_FALLBACK)

	/* Protocol name prefixes */
	NoisePrefixNONE     = NoisePrefix(C.NOISE_PREFIX_NONE)
	NoisePrefixCATEGORY = NoisePrefix(C.NOISE_PREFIX_CATEGORY)
	NoisePrefixSTANDARD = NoisePrefix(C.NOISE_PREFIX_STANDARD)
	NoisePrefixPSK      = NoisePrefix(C.NOISE_PREFIX_PSK)

	/* Signature algorithms */
	NoiseSignNONE     = NoiseSign(C.NOISE_SIGN_NONE)
	NoiseSignCATEGORY = NoiseSign(C.NOISE_SIGN_CATEGORY)
	NoiseSignED25519  = NoiseSign(C.NOISE_SIGN_ED25519)

	/* Actions for the application to take, as directed by the HandshakeState */
	NoiseActionNone         = NoiseAction(C.NOISE_ACTION_NONE)
	NoiseActionWriteMessage = NoiseAction(C.NOISE_ACTION_WRITE_MESSAGE)
	NoiseActionReadMessage  = NoiseAction(C.NOISE_ACTION_READ_MESSAGE)
	NoiseActionFailed       = NoiseAction(C.NOISE_ACTION_FAILED)
	NoiseActionSplit        = NoiseAction(C.NOISE_ACTION_SPLIT)
	NoiseActionComplete     = NoiseAction(C.NOISE_ACTION_COMPLETE)

	/* Maximum length of a packet payload */
	NoiseMaxPayloadLen = 65535
)

func (v *NoisePattern) Value(b byte) NoisePattern {
	*v = NoisePattern(20480 | uint16(b))
	return *v
}

func (v *NoiseDH) Value(b byte) NoiseDH {
	*v = NoiseDH(17408 | uint16(b))
	return *v
}

func (v *NoiseCipher) Value(b byte) NoiseCipher {
	*v = NoiseCipher(17152 | uint16(b))
	return *v
}

func (v *NoiseHash) Value(b byte) NoiseHash {
	*v = NoiseHash(18432 | uint16(b))
	return *v
}

func (s *HandshakeState) Init() error {
	if s.handshakeState == nil {
		var err C.int
		if s.Initiator {
			err = C.create_handshake(&s.handshakeState, C.NOISE_ROLE_INITIATOR, C.int(s.Prefix), C.int(s.Pattern), C.int(s.Dh), C.int(s.Cipher), C.int(s.Hash))
		} else {
			err = C.create_handshake(&s.handshakeState, C.NOISE_ROLE_RESPONDER, C.int(s.Prefix), C.int(s.Pattern), C.int(s.Dh), C.int(s.Cipher), C.int(s.Hash))
		}
		if err != C.NOISE_ERROR_NONE {
			return errors.New(strerror(err))
		}
	}
	return nil
}

func (s *HandshakeState) NeedsLocalKeyPair() bool {
	if s.handshakeState == nil {
		return false
	}
	return C.noise_handshakestate_needs_local_keypair(s.handshakeState) != C.int(0)
}

func (s *HandshakeState) SetLocalKeyPair(private []byte) error {
	if err := s.Init(); err != nil {
		return err
	}
	var err C.int
	dh := C.noise_handshakestate_get_local_keypair_dh(s.handshakeState)
	dhId := C.noise_dhstate_get_dh_id(dh)
	if dhId == C.NOISE_DH_CURVE25519 {
		err = C.noise_dhstate_set_keypair_private(dh, (*C.uint8_t)(unsafe.Pointer(&private[0])), C.size_t(len(private)))
	} else if dhId == C.NOISE_DH_CURVE448 {
		err = C.noise_dhstate_set_keypair_private(dh, (*C.uint8_t)(unsafe.Pointer(&private[0])), C.size_t(len(private)))
	} else {
		err = C.NOISE_ERROR_UNKNOWN_ID
	}
	if err != C.NOISE_ERROR_NONE {
		return errors.New(strerror(err))
	}
	return nil
}

func (s *HandshakeState) NeedsRemotePublicKey() bool {
	if s.handshakeState == nil {
		return false
	}
	return C.noise_handshakestate_needs_remote_public_key(s.handshakeState) != C.int(0)
}

func (s *HandshakeState) SetRemotePublicKey(public []byte) error {
	if err := s.Init(); err != nil {
		return err
	}
	var err C.int
	dh := C.noise_handshakestate_get_remote_public_key_dh(s.handshakeState)
	dhId := C.noise_dhstate_get_dh_id(dh)
	if dhId == C.NOISE_DH_CURVE25519 {
		err = C.noise_dhstate_set_public_key(dh, (*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(len(public)))
	} else if dhId == C.NOISE_DH_CURVE448 {
		err = C.noise_dhstate_set_public_key(dh, (*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(len(public)))
	} else {
		err = C.NOISE_ERROR_UNKNOWN_ID
	}
	if err != C.NOISE_ERROR_NONE {
		return errors.New(strerror(err))
	}
	return nil
}

func (s *HandshakeState) GetRemotePublicKey() (public []byte, _ error) {
	if s.handshakeState == nil {
		return nil, nil
	}
	if C.noise_handshakestate_has_remote_public_key(s.handshakeState) != C.int(0) {
		var err C.int
		dh := C.noise_handshakestate_get_remote_public_key_dh(s.handshakeState)
		dhId := C.noise_dhstate_get_dh_id(dh)
		if dhId == C.NOISE_DH_CURVE25519 {
			public = make([]byte, 32)
			err = C.noise_dhstate_get_public_key(dh, (*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(32))
		} else if dhId == C.NOISE_DH_CURVE448 {
			public = make([]byte, 56)
			err = C.noise_dhstate_get_public_key(dh, (*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(56))
		} else {
			err = C.NOISE_ERROR_UNKNOWN_ID
		}
		if err != C.NOISE_ERROR_NONE {
			return nil, errors.New(strerror(err))
		}
	}
	return public, nil
}

func (s *HandshakeState) GetLocalPublicKey() (public []byte, _ error) {
	if s.handshakeState == nil {
		return nil, nil
	}
	if C.noise_handshakestate_has_local_keypair(s.handshakeState) != C.int(0) {
		var err C.int
		dh := C.noise_handshakestate_get_local_keypair_dh(s.handshakeState)
		dhId := C.noise_dhstate_get_dh_id(dh)
		if dhId == C.NOISE_DH_CURVE25519 {
			public = make([]byte, 32)
			err = C.noise_dhstate_get_public_key(dh, (*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(32))
		} else if dhId == C.NOISE_DH_CURVE448 {
			public = make([]byte, 56)
			err = C.noise_dhstate_get_public_key(dh, (*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(56))
		} else {
			err = C.NOISE_ERROR_UNKNOWN_ID
		}
		if err != C.NOISE_ERROR_NONE {
			return nil, errors.New(strerror(err))
		}
	}
	return public, nil
}

func (s *HandshakeState) HasRemotePublicKey(public []byte) bool {
	if s.handshakeState == nil {
		return false
	}
	return C.noise_handshakestate_has_remote_public_key(s.handshakeState) != C.int(0)
}

// Sets the prologue in the underlying handshakeState.
func (s *HandshakeState) SetPrologue(prologue []byte) error {
	if prologue == nil {
		return nil
	}
	if err := s.Init(); err != nil {
		return err
	}
	err := C.noise_handshakestate_set_prologue(s.handshakeState, unsafe.Pointer(&prologue[0]), C.size_t(len(prologue)))
	if err != C.NOISE_ERROR_NONE {
		return errors.New(strerror(err))
	}
	return nil
}

// Start starts the underlying handshakeState.
func (s *HandshakeState) Start() error {
	if err := s.Init(); err != nil {
		return err
	}
	err := C.noise_handshakestate_start(s.handshakeState)
	if err != C.NOISE_ERROR_NONE {
		return errors.New(strerror(err))
	}
	return nil
}

func (s *HandshakeState) GetAction() NoiseAction {
	if s.handshakeState == nil {
		return NoiseActionNone
	}
	return NoiseAction(C.noise_handshakestate_get_action(s.handshakeState))
}

// WriteMessage appends a handshake message to out. The message will include the
// optional payload if provided. It is an error to call this method out of
// sync with the handshake pattern.
func (s *HandshakeState) WriteMessage(out, payload []byte) ([]byte, error) {
	var err C.int
	if out == nil {
		out = make([]byte, 1, len(payload)+(2*56)+(3*16)) //e, ee, se, s, es + payload
	}
	size := C.size_t(cap(out))
	if payload != nil {
		err = C.write_handshake(s.handshakeState,
			(*C.uint8_t)(unsafe.Pointer(&out[0])), &size,
			(*C.uint8_t)(unsafe.Pointer(&payload[0])), C.size_t(len(payload)))
	} else {
		err = C.write_handshake(s.handshakeState, (*C.uint8_t)(unsafe.Pointer(&out[0])), &size, nil, C.size_t(0))
	}
	if err != C.NOISE_ERROR_NONE {
		return nil, errors.New(strerror(err))
	}
	//log.Infof("Write Handshake: len(%d) - %x", size, out[:size])
	return out[:size], nil
}

// ReadMessage processes a received handshake message and appends the payload,
// if any to out. It is an error to call this method out of sync with the handshake pattern.
func (s *HandshakeState) ReadMessage(out, in []byte) ([]byte, error) {
	if out == nil {
		out = make([]byte, len(in))
	}
	//log.Infof("Read Handshake: len(%d) - %x", len(in), in)
	size := C.size_t(cap(out))
	err := C.read_handshake(s.handshakeState, (*C.uint8_t)(unsafe.Pointer(&in[0])), C.size_t(len(in)), (*C.uint8_t)(unsafe.Pointer(&out[0])), &size)
	if err != C.NOISE_ERROR_NONE {
		return nil, errors.New(strerror(err))
	}
	return out[:size], nil
}

func (s *HandshakeState) GetHandshakeHash() ([]byte, error) {
	var hash []byte
	if s.Hash == NoiseHashSHA256 || s.Hash == NoiseHashBLAKE2s {
		hash = make([]byte, 32)
	} else {
		hash = make([]byte, 64)
	}
	err := C.noise_handshakestate_get_handshake_hash(s.handshakeState, (*C.uint8_t)(unsafe.Pointer(&hash[0])), C.size_t(len(hash)))
	if err != C.NOISE_ERROR_NONE {
		return nil, errors.New(strerror(err))
	}
	return hash, nil
}

// If the handshake is completed by the call, two
// CipherStates will be returned, one is used for encryption of messages to the
// remote peer, the other is used for decryption of messages from the remote
// peer
func (s *HandshakeState) Split() (*CipherState, *CipherState, error) {
	sendCipher, recvCipher := &CipherState{}, &CipherState{}

	err := C.noise_handshakestate_split(s.handshakeState, &sendCipher.cipherState, &recvCipher.cipherState)
	if err != C.NOISE_ERROR_NONE {
		return nil, nil, errors.New(strerror(err))
	}
	return sendCipher, recvCipher, nil
}

// Destroy destroys the underlying C handshakeState.
func (s *HandshakeState) Destroy() {
	C.noise_handshakestate_free(s.handshakeState)
	s.handshakeState = nil
}

// Encrypt encrypts the plaintext and then appends the ciphertext and an
// authentication tag across the ciphertext and optional authenticated data to
// out. This method automatically increments the nonce after every call, so
// messages must be decrypted in the same order.
func (s *CipherState) Encrypt(ad, plaintext []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, nil
	}
	size := len(plaintext)
	if size > NoiseMaxPayloadLen-16 {
		return nil, errors.Errorf("too big message max[65516]/msg[%d]", size)
	}

	if cap(plaintext) < size+16 {
		t := make([]byte, len(plaintext)+16)
		copy(t, plaintext)
		plaintext = t
	}

	nBytes := (C.size_t)(size)
	var err C.int
	if ad != nil {
		err = C.cipherstate_encrypt_with_ad(s.cipherState,
			(*C.uint8_t)(unsafe.Pointer(&ad[0])), C.size_t(len(ad)),
			(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), &nBytes, C.size_t(cap(plaintext)))
	} else {
		err = C.cipherstate_encrypt_with_ad(s.cipherState, nil, 0,
			(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), &nBytes, C.size_t(cap(plaintext)))
	}

	if err != C.NOISE_ERROR_NONE {
		return nil, errors.New(strerror(err))
	}
	return plaintext[:nBytes], nil
	return nil, nil
}

// Decrypt checks the authenticity of the ciphertext and authenticated data and
// then decrypts and appends the plaintext to out. This method automatically
// increments the nonce after every call, messages must be provided in the same
// order that they were encrypted with no missing messages.
func (s *CipherState) Decrypt(ad, ciphertext []byte) ([]byte, error) {
	var err C.int
	size := C.size_t(len(ciphertext))

	if ad != nil {
		err = C.cipherstate_decrypt_with_ad(s.cipherState,
			(*C.uint8_t)(unsafe.Pointer(&ad[0])), C.size_t(len(ad)),
			(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), &size, C.size_t(len(ciphertext)))
	} else {
		err = C.cipherstate_decrypt_with_ad(s.cipherState, nil, 0,
			(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), &size, C.size_t(len(ciphertext)))
	}

	if err != C.NOISE_ERROR_NONE {
		return nil, errors.New(strerror(err))
	}
	return ciphertext[:size], nil
}

func (s *CipherState) Rekey() error {
	return errors.New("not supported")
}

// Destroy destroys the underlying C cipherState.
func (s *CipherState) Destroy() {
	C.noise_cipherstate_free(s.cipherState)
}

func GenerateX448KeyPair() ([]byte, []byte, error) {
	public := make([]byte, 56)
	private := make([]byte, 56)

	err := C.generate_key(
		C.NOISE_DH_CURVE448,
		(*C.uint8_t)(unsafe.Pointer(&private[0])), C.size_t(len(private)),
		(*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(len(public)))
	if err != C.NOISE_ERROR_NONE {
		return nil, nil, errors.New(strerror(err))
	}
	return public, private, nil
}

func GenerateX25519KeyPair() ([]byte, []byte, error) {
	public := make([]byte, 32)
	private := make([]byte, 32)

	err := C.generate_key(
		C.NOISE_DH_CURVE25519,
		(*C.uint8_t)(unsafe.Pointer(&private[0])), C.size_t(len(private)),
		(*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(len(public)))
	if err != C.NOISE_ERROR_NONE {
		return nil, nil, errors.New(strerror(err))
	}
	return public, private, nil
}

// Formats the fingerprint for a raw public key value.
func FullFingerprint(public []byte) (string, error) {
	if public == nil || (len(public) != 56 && len(public) != 32) {
		return "", errors.New("Invalid key length")
	}
	buf := make([]byte, 96)
	err := C.noise_format_fingerprint(
		C.NOISE_FINGERPRINT_FULL,
		(*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)),
		(*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(len(public)))
	if err != C.NOISE_ERROR_NONE {
		return "", errors.New(strerror(err))
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), nil
}

// Formats the fingerprint for a raw public key value.
func BasicFingerprint(public []byte) (string, error) {
	if public == nil || (len(public) != 56 && len(public) != 32) {
		return "", errors.New("Invalid key length")
	}
	buf := make([]byte, 48)
	err := C.noise_format_fingerprint(
		C.NOISE_FINGERPRINT_BASIC,
		(*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)),
		(*C.uint8_t)(unsafe.Pointer(&public[0])), C.size_t(len(public)))
	if err != C.NOISE_ERROR_NONE {
		return "", errors.New(strerror(err))
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), nil
}

func strerror(code C.int) string {
	buf := make([]byte, 32)
	if C.noise_strerror(code, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(32)) != C.int(0) {
		return fmt.Sprintf("Unknown error 0x%X", int(code))
	}
	msg := C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
	return msg
}
