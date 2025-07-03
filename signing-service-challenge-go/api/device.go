package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/crypto"
	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/domain"
)

type createSignatureDeviceRequest struct {
	ID        string `json:"id"` // Could be a UUID
	Algorithm string `json:"algorithm"`
	Label     string `json:"label,omitempty"`
}

type createSignatureDeviceResponse struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
	Label     string `json:"label,omitempty"`
	PublicKey string `json:"public_key"` // base64 encoded
}

func (s *Server) CreateSignatureDevice(w http.ResponseWriter, r *http.Request) {
	var req createSignatureDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var (
		publicKey  []byte
		privateKey []byte
	)

	switch req.Algorithm {
	case "ECC":
		generator := crypto.ECCGenerator{}
		keypair, err := generator.Generate()
		if err != nil {
			http.Error(w, "key generation failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		publicKey = marshalECCPublicKey(keypair.Public)
		privateKey = marshalECCPrivateKey(keypair.Private)

	case "RSA":
		generator := crypto.RSAGenerator{}
		keypair, err := generator.Generate()
		if err != nil {
			http.Error(w, "key generation failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		publicKey = marshalRSAPublicKey(keypair.Public)
		privateKey = marshalRSAPrivateKey(keypair.Private)

	default:
		http.Error(w, "unsupported algorithm", http.StatusBadRequest)
		return
	}

	device := domain.SignatureDevice{
		ID:         req.ID,
		Algorithm:  req.Algorithm,
		Label:      req.Label,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
	if err := s.store.Create(device); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := createSignatureDeviceResponse{
		ID:        device.ID,
		Algorithm: device.Algorithm,
		Label:     device.Label,
		PublicKey: base64.StdEncoding.EncodeToString(device.PublicKey),
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func marshalECCPublicKey(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func marshalECCPrivateKey(priv *ecdsa.PrivateKey) []byte {
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	return keyBytes
}

func marshalRSAPublicKey(pub *rsa.PublicKey) []byte {
	keyBytes, _ := x509.MarshalPKIXPublicKey(pub)
	return keyBytes
}

func marshalRSAPrivateKey(priv *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(priv)
}
