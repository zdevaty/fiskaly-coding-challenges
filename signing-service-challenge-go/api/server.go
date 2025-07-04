package api

import (
	"encoding/json"
	"net/http"

	"github.com/zdevaty/fiskaly-coding-challenges/signing-service-challenge/persistence"
)

// Response is the generic API response container.
type Response struct {
	Data interface{} `json:"data"`
}

// ErrorResponse is the generic error API response container.
type ErrorResponse struct {
	Errors []string `json:"errors"`
}

// Server manages HTTP requests and dispatches them to the appropriate services.
type Server struct {
	listenAddress string
	store         persistence.DeviceStore
	Mux           *http.ServeMux // Makes mux available for testing
}

func NewServer(listenAddress string, store persistence.DeviceStore) *Server {
	mux := http.NewServeMux()
	server := &Server{
		listenAddress: listenAddress,
		store:         store,
		Mux:           mux,
	}

	mux.HandleFunc("GET /api/v0/health", server.Health)
	mux.HandleFunc("POST /api/v0/devices", server.CreateSignatureDevice)
	mux.HandleFunc("POST /api/v0/devices/{id}/sign", server.SignData)
	return server
}

func (s *Server) Run() error {
	return http.ListenAndServe(s.listenAddress, s.Mux)
}

// WriteInternalError writes a default internal error message as an HTTP response.
func WriteInternalError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
}

// WriteErrorResponse takes an HTTP status code and a slice of errors
// and writes those as an HTTP error response in a structured format.
func WriteErrorResponse(w http.ResponseWriter, code int, errors []string) {
	w.WriteHeader(code)

	errorResponse := ErrorResponse{
		Errors: errors,
	}

	bytes, err := json.Marshal(errorResponse)
	if err != nil {
		WriteInternalError(w)
	}

	w.Write(bytes)
}

// WriteAPIResponse takes an HTTP status code and a generic data struct
// and writes those as an HTTP response in a structured format.
func WriteAPIResponse(w http.ResponseWriter, code int, data interface{}) {
	w.WriteHeader(code)

	response := Response{
		Data: data,
	}

	bytes, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		WriteInternalError(w)
	}

	w.Write(bytes)
}
