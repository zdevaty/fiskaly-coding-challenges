package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/api"
	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/domain"
	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/persistence"
)

func setupTestServer() (*api.Server, *persistence.InMemoryDeviceStore) {
	store := persistence.NewInMemoryDeviceStore()
	server := api.NewServer(":8080", store)

	createReq := map[string]string{
		"id":        "test-device",
		"algorithm": domain.AlgorithmECC,
		"label":     "Test Device",
	}
	reqBody, _ := json.Marshal(createReq)

	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices",
		bytes.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	setupMux := http.NewServeMux()
	setupMux.HandleFunc("POST /api/v0/devices", server.CreateSignatureDevice)

	setupMux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		panic(fmt.Sprintf("failed to create test device: status %d, body %s", rr.Code, rr.Body.String()))
	}

	return server, store
}

func TestSignData(t *testing.T) {
	server, store := setupTestServer()

	tests := []struct {
		name           string
		deviceID       string
		requestBody    string
		expectedStatus int
		validate       func(t *testing.T, resp *api.SignResponse)
	}{
		{
			name:           "First signature",
			deviceID:       "test-device",
			requestBody:    `{"data_to_be_signed": "first test"}`,
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, resp *api.SignResponse) {
				assert.Contains(t, resp.SignedData, "0_first test")
				updatedDevice, err := store.Get("test-device")
				require.NoError(t, err)
				assert.Equal(t, uint64(1), updatedDevice.SignatureCounter)
				assert.NotEmpty(t, updatedDevice.LastSignature)
			},
		},
		// Here be further tests for various api edge cases
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(
				"POST",
				"/api/v0/devices/"+tt.deviceID+"/sign",
				bytes.NewBufferString(tt.requestBody),
			)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			// Route the request through the ServeMux so that path params are passed
			server.Mux.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code, "unexpected status code")

			if tt.expectedStatus == http.StatusOK {
				var resp api.Response
				err := json.NewDecoder(rr.Body).Decode(&resp)
				assert.NoError(t, err, "failed to decode response")
				data, ok := resp.Data.(map[string]interface{})
				assert.True(t, ok, "response data should be a map")
				signResp := api.SignResponse{
					Signature:  data["signature"].(string),
					SignedData: data["signed_data"].(string),
				}
				if tt.validate != nil {
					tt.validate(t, &signResp)
				}
			} else {
				// Test user error handling
			}
		})
	}
}
