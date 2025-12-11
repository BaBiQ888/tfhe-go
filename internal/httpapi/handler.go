package httpapi

import (
	"encoding/json"
	"net/http"

	"tfhe-go/internal/tfhe"
)

// Handler wires HTTP endpoints to the BooleanService.
type Handler struct {
	boolean *tfhe.BooleanService
	uint8   *tfhe.Uint8Service
}

// NewHandler builds a handler with dependencies injected.
func NewHandler(booleanService *tfhe.BooleanService, uint8Service *tfhe.Uint8Service) *Handler {
	return &Handler{
		boolean: booleanService,
		uint8:   uint8Service,
	}
}

// Register attaches routes to the provided mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.health)
	mux.HandleFunc("/boolean/encrypt", h.encrypt)
	mux.HandleFunc("/boolean/decrypt", h.decrypt)
	mux.HandleFunc("/boolean/and", h.and)
	mux.HandleFunc("/boolean/or", h.or)
	mux.HandleFunc("/boolean/xor", h.xor)
	mux.HandleFunc("/boolean/not", h.not)
	mux.HandleFunc("/uint8/encrypt", h.encryptUint8)
	mux.HandleFunc("/uint8/encrypt/public", h.encryptUint8Public)
	mux.HandleFunc("/uint8/decrypt", h.decryptUint8)
	mux.HandleFunc("/uint8/add", h.addUint8)
	mux.HandleFunc("/uint8/bitand", h.bitAndUint8)
	mux.HandleFunc("/uint8/bitxor", h.bitXorUint8)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) encrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Value bool `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ct, err := h.boolean.EncryptBoolToBase64(req.Value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": ct})
}

func (h *Handler) decrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	value, err := h.boolean.DecryptBoolFromBase64(req.Ciphertext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"value": value})
}

func (h *Handler) and(w http.ResponseWriter, r *http.Request) {
	h.binaryOp(w, r, h.boolean.AndBase64)
}

func (h *Handler) or(w http.ResponseWriter, r *http.Request) {
	h.binaryOp(w, r, h.boolean.OrBase64)
}

func (h *Handler) xor(w http.ResponseWriter, r *http.Request) {
	h.binaryOp(w, r, h.boolean.XorBase64)
}

func (h *Handler) not(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ct, err := h.boolean.NotBase64(req.Ciphertext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": ct})
}

type opFunc func(lhs, rhs string) (string, error)

func (h *Handler) binaryOp(w http.ResponseWriter, r *http.Request, fn opFunc) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Left  string `json:"left"`
		Right string `json:"right"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ct, err := fn(req.Left, req.Right)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": ct})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (h *Handler) encryptUint8(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Value uint8 `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ct, err := h.uint8.Encrypt(req.Value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": ct})
}

func (h *Handler) encryptUint8Public(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Value uint8 `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ct, err := h.uint8.EncryptWithPublic(req.Value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": ct})
}

func (h *Handler) decryptUint8(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	value, err := h.uint8.Decrypt(req.Ciphertext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]uint8{"value": value})
}

func (h *Handler) addUint8(w http.ResponseWriter, r *http.Request) {
	h.binaryOpUint8(w, r, h.uint8.Add)
}

func (h *Handler) bitAndUint8(w http.ResponseWriter, r *http.Request) {
	h.binaryOpUint8(w, r, h.uint8.BitAnd)
}

func (h *Handler) bitXorUint8(w http.ResponseWriter, r *http.Request) {
	h.binaryOpUint8(w, r, h.uint8.BitXor)
}

type uint8OpFunc func(lhs, rhs string) (string, error)

func (h *Handler) binaryOpUint8(w http.ResponseWriter, r *http.Request, fn uint8OpFunc) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Left  string `json:"left"`
		Right string `json:"right"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ct, err := fn(req.Left, req.Right)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": ct})
}
