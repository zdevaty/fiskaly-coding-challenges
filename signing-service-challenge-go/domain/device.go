package domain

import "sync/atomic"

type SignatureDevice struct {
	ID               string
	Label            string
	Algorithm        string // could be of "Algorithm" type providing "enum-like" properties if desired
	PublicKey        []byte
	PrivateKey       []byte
	signatureCounter uint64
}

func (d *SignatureDevice) IncrementCounter() uint64 {
	return atomic.AddUint64(&d.signatureCounter, 1)
}

func (d *SignatureDevice) GetCounter() uint64 {
	return atomic.LoadUint64(&d.signatureCounter)
}
