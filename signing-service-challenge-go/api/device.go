package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/crypt"
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
		WriteErrorResponse(w, http.StatusInternalServerError, []string{"decoding request: " + err.Error()})
		return
	}

	var (
		publicKey  []byte
		privateKey []byte
	)

	switch req.Algorithm {
	case domain.AlgorithmECC:
		generator := crypt.ECCGenerator{}
		keypair, err := generator.Generate()
		if err != nil {
			WriteErrorResponse(w, http.StatusInternalServerError, []string{"ecc key generation failed: " + err.Error()})
			return
		}
		publicKey = marshalECCPublicKey(keypair.Public)
		privateKey = marshalECCPrivateKey(keypair.Private)

	case domain.AlgorithmRSA:
		generator := crypt.RSAGenerator{}
		keypair, err := generator.Generate()
		if err != nil {
			WriteErrorResponse(w, http.StatusInternalServerError, []string{"rsa key generation failed: " + err.Error()})
			return
		}
		publicKey = marshalRSAPublicKey(keypair.Public)
		privateKey = marshalRSAPrivateKey(keypair.Private)

	default:
		WriteErrorResponse(w, http.StatusBadRequest, []string{"Unsupported algorithm"})
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
		WriteErrorResponse(w, http.StatusInternalServerError, []string{"Failed to create device"})
		return
	}

	response := createSignatureDeviceResponse{
		ID:        device.ID,
		Algorithm: device.Algorithm,
		Label:     device.Label,
		PublicKey: base64.StdEncoding.EncodeToString(device.PublicKey),
	}

	WriteAPIResponse(w, http.StatusCreated, response)
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
