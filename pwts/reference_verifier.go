package main

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	ff "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

// ExpectedRSelContext is installed by the verifier, not taken from the proof.
// Message is a reference message ID; full DID/VC context encoding remains a
// separate integration requirement. The VK is selected out of band.
type ExpectedRSelContext struct {
	Epoch, Message, Policy, Threshold uint64
	RosterRoot                        F
	AuditPK                           bls.G1Affine
	RequestDigest                     []byte // Optional 32-byte SHA-256 digest of the complete request.
}

// VerifyReferenceRSel verifies decoded reference proof material with context
// binding, external hash-to-curve binding and native aggregate BLS verification.
// It does not validate DID/VC business predicates, finality or state transitions.
func VerifyReferenceRSel(proofBytes, publicBytes []byte, vk groth16.VerifyingKey, expected ExpectedRSelContext) error {
	if len(proofBytes) > 4096 || len(publicBytes) != 828 {
		return fmt.Errorf("invalid reference material size")
	}
	proof := groth16.NewProof(ecc.BW6_761)
	r := bytes.NewReader(proofBytes)
	if _, err := proof.ReadFrom(r); err != nil {
		return err
	}
	if r.Len() != 0 {
		return fmt.Errorf("trailing proof data")
	}
	pub, err := witness.New(ecc.BW6_761.ScalarField())
	if err != nil {
		return err
	}
	r = bytes.NewReader(publicBytes)
	if _, err = pub.ReadFrom(r); err != nil {
		return err
	}
	if r.Len() != 0 {
		return fmt.Errorf("trailing public data")
	}
	v, ok := pub.Vector().(ff.Vector)
	if !ok || len(v) != 17 {
		return fmt.Errorf("unexpected reference schema")
	}
	eq := func(index int, value F) bool { return v[index].Equal(&value) }
	message := num(expected.Message)
	h := messagePoint(expected.Message)
	if expected.RequestDigest != nil {
		if len(expected.RequestDigest) != 32 {
			return fmt.Errorf("invalid request digest length")
		}
		message.SetBytes(expected.RequestDigest)
		h, err = bls.HashToG1(expected.RequestDigest, []byte("EQUIDID_REQUEST_BLS12377G1_XMD:SHA-256_SSWU_RO_V1"))
		if err != nil {
			return err
		}
	}
	if !eq(0, num(expected.Epoch)) || !eq(1, message) || !eq(2, num(expected.Policy)) || !eq(3, num(expected.Threshold)) || !eq(4, expected.RosterRoot) {
		return fmt.Errorf("unexpected authorization context")
	}
	if !eq(13, coord(&h.X)) || !eq(14, coord(&h.Y)) {
		return fmt.Errorf("message point mismatch")
	}
	if !eq(15, coord(&expected.AuditPK.X)) || !eq(16, coord(&expected.AuditPK.Y)) {
		return fmt.Errorf("audit key mismatch")
	}
	var sig bls.G1Affine
	var pk bls.G2Affine
	sig.X.SetBigInt(integer(&v[11]))
	sig.Y.SetBigInt(integer(&v[12]))
	pk.X.A0.SetBigInt(integer(&v[7]))
	pk.X.A1.SetBigInt(integer(&v[8]))
	pk.Y.A0.SetBigInt(integer(&v[9]))
	pk.Y.A1.SetBigInt(integer(&v[10]))
	if sig.IsInfinity() || pk.IsInfinity() || !sig.IsInSubGroup() || !pk.IsInSubGroup() {
		return fmt.Errorf("invalid aggregate point")
	}
	if err = groth16.Verify(proof, vk, pub); err != nil {
		return err
	}
	_, _, _, g2 := bls.Generators()
	g2.Neg(&g2)
	ok, err = bls.PairingCheck([]bls.G1Affine{sig, h}, []bls.G2Affine{g2, pk})
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("invalid aggregate signature")
	}
	return nil
}
