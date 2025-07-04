package domain

const (
	AlgorithmECC string = "ECC"
	AlgorithmRSA string = "RSA"
)

type SignatureDevice struct {
	ID               string
	Label            string
	Algorithm        string // could be of "Algorithm" type providing "enum-like" properties if desired
	PublicKey        []byte
	PrivateKey       []byte
	SignatureCounter uint64
	LastSignature    string
}
