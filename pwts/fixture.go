package main

import (
	"fmt"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	sw "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"math/big"
)

type Fixture struct {
	Circuit, Witness RSelCircuit
	Audit            *AuditState
	Tags             []AuditTag
	Signatures       []bls.G1Affine
	Keys             []bls.G2Affine
	Secrets          []S // Local reference members only; never serialized in certificates.
}

func makeFixture(n int) (*Fixture, error) {
	if n < 1 {
		return nil, fmt.Errorf("selected signer count must be positive")
	}
	audit, err := DKG(n, (n/2)+1, 1)
	if err != nil {
		return nil, err
	}
	_, _, _, g2 := bls.Generators()
	msg := num(555)
	h := messagePoint(555)
	c := RSelCircuit{Slots: make([]Slot, n)}
	w := RSelCircuit{Slots: make([]Slot, n)}
	var aggSig bls.G1Affine
	var aggPK bls.G2Affine
	var total uint64
	rosterLeaves := make([]F, n)
	auditLeaves := make([]F, n)
	tags := make([]AuditTag, n)
	sigs := make([]bls.G1Affine, n)
	keys := make([]bls.G2Affine, n)
	secrets := make([]S, n)
	for i := 0; i < n; i++ {
		sk := randomScalar()
		secrets[i] = sk
		pk := g2mul(g2, sk)
		sig := g1mul(h, sk)
		r := randomScalar()
		weight := uint64(1000 + i)
		tag := encryptTag(audit.PK, tagPlain(i+1, pk, msg, sig), msg, r)
		values := []F{num(1), num(uint64(i + 1))}
		values = append(values, g2Fields(pk)...)
		values = append(values, num(weight), num(1), num(77))
		rosterLeaves[i] = hashF(101, values...)
		auditLeaves[i] = tagHash(tag)
		w.Slots[i] = Slot{B: 1, PK: sw.NewG2Affine(pk), Sig: sw.NewG1Affine(sig), Weight: weight, Role: 1, TagE: sw.NewG1Affine(tag.E), R: integer(&r)}
		for j := range tag.C {
			w.Slots[i].TagC[j] = integer(&tag.C[j])
		}
		aggSig = g1add(aggSig, sig)
		aggPK = g2add(aggPK, pk)
		total += weight
		tags[i] = tag
		sigs[i] = sig
		keys[i] = pk
	}
	tree := func(v []F, domain uint64) F {
		for cap := 1; cap < len(v); cap <<= 1 {
			if cap<<1 >= len(v) {
				for len(v) < cap<<1 {
					v = append(v, hashF(domain, num(0), num(uint64(len(v)+1))))
				}
				break
			}
		}
		for len(v) > 1 {
			z := make([]F, len(v)/2)
			for i := range z {
				z[i] = hashF(domain, v[2*i], v[2*i+1])
			}
			v = z
		}
		return v[0]
	}
	for _, x := range []*RSelCircuit{&w} {
		x.Epoch = 1
		x.Message = integer(&msg)
		x.Policy = 77
		x.Threshold = total
		x.RealizedWeight = total
		x.RosterRoot = integerPtr(tree(rosterLeaves, 102))
		x.AuditRoot = integerPtr(tree(auditLeaves, 206))
		x.AggPK = sw.NewG2Affine(aggPK)
		x.AggSig = sw.NewG1Affine(aggSig)
		x.HPoint = sw.NewG1Affine(h)
		x.AuditPK = sw.NewG1Affine(audit.PK)
	}
	return &Fixture{Circuit: c, Witness: w, Audit: audit, Tags: tags, Signatures: sigs, Keys: keys, Secrets: secrets}, nil
}
func integerPtr(v F) *big.Int { return integer(&v) }
