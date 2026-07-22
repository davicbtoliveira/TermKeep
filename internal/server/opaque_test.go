package server

import "testing"

func TestNewOPAQUEServerUsesPersistentKeyMaterial(t *testing.T) {
	privateKey, oprfSeed, err := GenerateOPAQUEKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewOPAQUEServer(privateKey, oprfSeed); err != nil {
		t.Fatalf("NewOPAQUEServer() error = %v", err)
	}
	if _, err := NewOPAQUEServer("not-hex", oprfSeed); err == nil {
		t.Fatal("NewOPAQUEServer() accepted malformed private key")
	}
}
