package server

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bytemare/opaque"
)

// GenerateOPAQUEKeyMaterial creates the two persistent server secrets needed
// by OPAQUE. Operators must save both outputs before starting the service.
func GenerateOPAQUEKeyMaterial() (privateKey, oprfSeed string, err error) {
	configuration := opaque.DefaultConfiguration()
	private, _ := configuration.KeyGen()
	seed := configuration.GenerateOPRFSeed()
	return hex.EncodeToString(private.Encode()), hex.EncodeToString(seed), nil
}

// NewOPAQUEServer restores OPAQUE's persistent long-term key and OPRF seed.
// Changing either value makes existing accounts unable to authenticate.
func NewOPAQUEServer(privateKeyHex, oprfSeedHex string) (*opaque.Server, error) {
	if privateKeyHex == "" || oprfSeedHex == "" {
		return nil, errors.New("OPAQUE_SERVER_KEY and OPAQUE_OPRF_SEED are required")
	}
	configuration := opaque.DefaultConfiguration()
	deserializer, err := configuration.Deserializer()
	if err != nil {
		return nil, fmt.Errorf("create OPAQUE deserializer: %w", err)
	}
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, errors.New("decode OPAQUE server key")
	}
	privateKey, err := deserializer.DecodePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("decode OPAQUE server key: %w", err)
	}
	oprfSeed, err := hex.DecodeString(oprfSeedHex)
	if err != nil || len(oprfSeed) != configuration.Hash.Size() {
		return nil, errors.New("decode OPAQUE OPRF seed")
	}
	opaqueServer, err := opaque.NewServer(configuration)
	if err != nil {
		return nil, fmt.Errorf("create OPAQUE server: %w", err)
	}
	publicKey := configuration.AKE.Group().Base().Multiply(privateKey).Encode()
	if err := opaqueServer.SetKeyMaterial(&opaque.ServerKeyMaterial{
		PrivateKey:     privateKey,
		PublicKeyBytes: publicKey,
		OPRFGlobalSeed: oprfSeed,
	}); err != nil {
		return nil, fmt.Errorf("configure OPAQUE server: %w", err)
	}
	return opaqueServer, nil
}
