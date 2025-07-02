package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

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

	// todo: verify algorithm
	var publicKey, privateKey []byte
	// todo: generate keys

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
		Algorithm: string(device.Algorithm),
		Label:     device.Label,
		PublicKey: base64.StdEncoding.EncodeToString(device.PublicKey),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
