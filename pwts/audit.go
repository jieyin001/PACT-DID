package main

import (
	"errors"
	"fmt"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

// Logical-party reference driver. Never reconstructs the joint secret.
// Private channels, authenticated broadcast and OS-level erasure are deployment assumptions.
type AuditState struct {
	Epoch     uint64
	IDs       []int
	Threshold int
	PK        bls.G1Affine
	VK        map[int]bls.G1Affine
	shares    map[int]S
	Retired   bool
}
type AuditTag struct {
	E bls.G1Affine
	C [7]F
}
type OpeningShare struct {
	Epoch   uint64
	ID      int
	D, A, B bls.G1Affine
	Z       S
}

func generator1() bls.G1Affine { _, _, g, _ := bls.Generators(); return g }

// Feldman-VSS DKG with fail-closed validation; no robust complaint recovery is claimed.
func DKG(n, t int, epoch uint64) (*AuditState, error) {
	if t < 1 || t > n {
		return nil, errors.New("invalid audit threshold")
	}
	ids := make([]int, n)
	for i := range ids {
		ids[i] = i + 1
	}
	a := &AuditState{Epoch: epoch, IDs: ids, Threshold: t, VK: map[int]bls.G1Affine{}, shares: map[int]S{}}
	g := generator1()
	for range ids {
		coeff := make([]S, t)
		com := make([]bls.G1Affine, t)
		for j := range coeff {
			coeff[j] = randomScalar()
			com[j] = g1mul(g, coeff[j])
		}
		a.PK = g1add(a.PK, com[0])
		for _, id := range ids {
			v := polyEval(coeff, id)
			actual := g1mul(g, v)
			expected := commitEval(com, id)
			if !actual.Equal(&expected) {
				return nil, errors.New("invalid DKG share")
			}
			old := a.shares[id]
			old.Add(&old, &v)
			a.shares[id] = old
		}
		for j := range coeff {
			coeff[j].SetZero()
		}
	}
	if a.PK.IsInfinity() {
		return nil, errors.New("identity audit key")
	}
	for _, id := range ids {
		a.VK[id] = g1mul(g, a.shares[id])
	}
	return a, nil
}

func tagPlain(id int, pk bls.G2Affine, msg F, sig bls.G1Affine) [7]F {
	p := [7]F{num(uint64(id))}
	copy(p[1:5], g2Fields(pk))
	p[5] = msg
	p[6] = hashF(204, g1Fields(sig)...)
	return p
}
func mask(shared, E bls.G1Affine, msg F, j int) F {
	v := append(g1Fields(shared), g1Fields(E)...)
	v = append(v, msg, num(uint64(j)))
	return hashF(303, v...)
}
func encryptTag(pkA bls.G1Affine, plain [7]F, msg F, r S) AuditTag {
	tag := AuditTag{E: g1mul(generator1(), r)}
	shared := g1mul(pkA, r)
	for j := range tag.C {
		m := mask(shared, tag.E, msg, j)
		tag.C[j].Add(&plain[j], &m)
	}
	return tag
}
func tagHash(tag AuditTag) F { v := append(g1Fields(tag.E), tag.C[:]...); return hashF(205, v...) }

func (s *AuditState) Partial(tag AuditTag, id int) (OpeningShare, error) {
	if s.Retired {
		return OpeningShare{}, errors.New("retired shares")
	}
	sk, ok := s.shares[id]
	if !ok {
		return OpeningShare{}, errors.New("unknown auditor")
	}
	if tag.E.IsInfinity() || !tag.E.IsInSubGroup() {
		return OpeningShare{}, errors.New("invalid ciphertext point")
	}
	g := generator1()
	r := randomScalar()
	p := OpeningShare{Epoch: s.Epoch, ID: id, D: g1mul(tag.E, sk), A: g1mul(g, r), B: g1mul(tag.E, r)}
	c := shaScalar("EquiDID-audit-dleq-v3", s.Epoch, id, g, s.PK, s.VK[id], tag.E, p.D, p.A, p.B)
	p.Z.Mul(&c, &sk)
	p.Z.Add(&p.Z, &r)
	return p, nil
}
func (s *AuditState) VerifyPartial(tag AuditTag, p OpeningShare) bool {
	vk, ok := s.VK[p.ID]
	if !ok || p.Epoch != s.Epoch || tag.E.IsInfinity() {
		return false
	}
	for _, point := range []bls.G1Affine{vk, tag.E, p.D, p.A, p.B} {
		if !point.IsInSubGroup() {
			return false
		}
	}
	g := generator1()
	c := shaScalar("EquiDID-audit-dleq-v3", s.Epoch, p.ID, g, s.PK, vk, tag.E, p.D, p.A, p.B)
	l1 := g1mul(g, p.Z)
	r1 := g1add(p.A, g1mul(vk, c))
	l2 := g1mul(tag.E, p.Z)
	r2 := g1add(p.B, g1mul(p.D, c))
	return l1.Equal(&r1) && l2.Equal(&r2)
}
func (s *AuditState) Open(tag AuditTag, msg F, parts []OpeningShare) ([7]F, error) {
	var plain [7]F
	if len(parts) < s.Threshold {
		return plain, errors.New("insufficient opening shares")
	}
	seen := map[int]bool{}
	ids := make([]int, len(parts))
	for i, p := range parts {
		if seen[p.ID] || !s.VerifyPartial(tag, p) {
			return plain, errors.New("invalid or duplicate opening share")
		}
		seen[p.ID] = true
		ids[i] = p.ID
	}
	var shared bls.G1Affine
	for _, p := range parts {
		shared = g1add(shared, g1mul(p.D, lagrange(ids, p.ID)))
	}
	for j := range plain {
		m := mask(shared, tag.E, msg, j)
		plain[j].Sub(&tag.C[j], &m)
	}
	if !plain[5].Equal(&msg) {
		return plain, errors.New("opening context mismatch")
	}
	return plain, nil
}

// Same-committee zero-constant refresh; cross-committee handover uses old qualified dealers.
func (old *AuditState) Evolve(newN, newT int, handover bool) (*AuditState, error) {
	if old.Retired || newT < 1 || newT > newN {
		return nil, errors.New("invalid evolution")
	}
	if !handover && (newN != len(old.IDs) || newT != old.Threshold) {
		return nil, errors.New("refresh must preserve committee")
	}
	ids := make([]int, newN)
	for i := range ids {
		if handover {
			ids[i] = 1000 + int(old.Epoch)*100 + i
		} else {
			ids[i] = old.IDs[i]
		}
	}
	out := &AuditState{Epoch: old.Epoch + 1, IDs: ids, Threshold: newT, PK: old.PK, VK: map[int]bls.G1Affine{}, shares: map[int]S{}}
	dealers := old.IDs
	if handover {
		dealers = dealers[:old.Threshold]
	}
	g := generator1()
	var constants bls.G1Affine
	if !handover {
		for _, id := range ids {
			out.shares[id] = old.shares[id]
		}
	}
	for _, dealer := range dealers {
		coeff := make([]S, newT)
		com := make([]bls.G1Affine, newT)
		if handover {
			sk := old.shares[dealer]
			l := lagrange(dealers, dealer)
			coeff[0].Mul(&sk, &l)
		}
		for j := 1; j < newT; j++ {
			coeff[j] = randomScalar()
		}
		for j := range coeff {
			com[j] = g1mul(g, coeff[j])
		}
		if handover {
			expected := g1mul(old.VK[dealer], lagrange(dealers, dealer))
			if !com[0].Equal(&expected) {
				return nil, errors.New("bad handover constant")
			}
		}
		if !handover && !com[0].IsInfinity() {
			return nil, errors.New("nonzero refresh constant")
		}
		constants = g1add(constants, com[0])
		for _, id := range ids {
			v := polyEval(coeff, id)
			actual := g1mul(g, v)
			expected := commitEval(com, id)
			if !actual.Equal(&expected) {
				return nil, fmt.Errorf("invalid resharing share for %d", id)
			}
			x := out.shares[id]
			x.Add(&x, &v)
			out.shares[id] = x
		}
		for j := range coeff {
			coeff[j].SetZero()
		}
	}
	if handover && !constants.Equal(&old.PK) {
		return nil, errors.New("handover changed audit key")
	}
	for _, id := range ids {
		out.VK[id] = g1mul(g, out.shares[id])
	}
	// Logical retirement and best-effort zeroization only; Go may retain copies.
	for id, v := range old.shares {
		v.SetZero()
		old.shares[id] = v
	}
	old.Retired = true
	return out, nil
}
