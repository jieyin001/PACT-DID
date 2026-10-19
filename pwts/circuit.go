package main

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	sw "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Slot struct {
	B      frontend.Variable
	PK     sw.G2Affine
	Sig    sw.G1Affine
	Weight frontend.Variable
	Role   frontend.Variable
	TagE   sw.G1Affine
	TagC   [7]frontend.Variable
	R      frontend.Variable
}
type RSelCircuit struct {
	// Compile-time ablation only. Never select this from untrusted wire data.
	DisableAudit                          bool              `gnark:"-"`
	Epoch, Message, Policy, Threshold     frontend.Variable `gnark:",public"`
	RosterRoot, AuditRoot, RealizedWeight frontend.Variable `gnark:",public"`
	AggPK                                 sw.G2Affine       `gnark:",public"`
	AggSig                                sw.G1Affine       `gnark:",public"`
	HPoint                                sw.G1Affine       `gnark:",public"`
	AuditPK                               sw.G1Affine       `gnark:",public"`
	Slots                                 []Slot
}

func circuitHash(api frontend.API, domain frontend.Variable, values ...frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	h.Write(domain)
	h.Write(values...)
	return h.Sum()
}
func g1vars(p sw.G1Affine) []frontend.Variable { return []frontend.Variable{p.X, p.Y} }
func g2vars(p sw.G2Affine) []frontend.Variable {
	return []frontend.Variable{p.P.X.A0, p.P.X.A1, p.P.Y.A0, p.P.Y.A1}
}
func tagVars(s Slot) []frontend.Variable { v := g1vars(s.TagE); v = append(v, s.TagC[:]...); return v }
func root(api frontend.API, values []frontend.Variable, domain frontend.Variable) frontend.Variable {
	if len(values) == 0 {
		panic("at least one leaf required")
	}
	// Pad only the Merkle layer, not the signer list. This permits exact
	// non-power-of-two signer counts while retaining one validity equation for
	// every selected member. Padding leaves are deterministic and carry no
	// signer witness.
	for cap := 1; cap < len(values); cap <<= 1 {
		if cap<<1 >= len(values) {
			for len(values) < cap<<1 {
				values = append(values, circuitHash(api, domain, 0, len(values)+1))
			}
			break
		}
	}
	for len(values) > 1 {
		next := make([]frontend.Variable, len(values)/2)
		for i := range next {
			next[i] = circuitHash(api, domain, values[2*i], values[2*i+1])
		}
		values = next
	}
	return values[0]
}
func (c *RSelCircuit) Define(api frontend.API) error {
	if len(c.Slots) == 0 {
		return fmt.Errorf("invalid capacity")
	}
	pair := sw.NewPairing(api)
	pair.AssertIsOnG1(&c.AggSig)
	pair.AssertIsOnG1(&c.HPoint)
	pair.AssertIsOnG2(&c.AggPK)
	if !c.DisableAudit {
		pair.AssertIsOnG1(&c.AuditPK)
	}
	rosterLeaves := make([]frontend.Variable, len(c.Slots))
	auditLeaves := make([]frontend.Variable, len(c.Slots))
	total := frontend.Variable(0)
	var aggSig sw.G1Affine
	aggSig.X = 0
	aggSig.Y = 0
	var aggPK sw.G2Affine
	aggPK.P.X.A0 = 0
	aggPK.P.X.A1 = 0
	aggPK.P.Y.A0 = 0
	aggPK.P.Y.A1 = 0
	g1 := sw.NewG1Affine(generator1())
	_, _, _, g2n := blsGenerators()
	g2 := sw.NewG2Affine(g2n)
	negG2 := g2
	negG2.P.Neg(api, g2.P)
	for i := range c.Slots {
		s := &c.Slots[i]
		// This reference circuit is instantiated for the selected list itself.
		// Thus every slot is a selected member; no padding slot can bypass a
		// per-share verification equation.
		api.AssertIsEqual(s.B, 1)
		api.ToBinary(s.Weight, 32)
		pair.AssertIsOnG1(&s.Sig)
		pair.AssertIsOnG2(&s.PK)
		if !c.DisableAudit {
			pair.AssertIsOnG1(&s.TagE)
		}
		// Role 1 is the reference policy. Policy ID is bound into every roster leaf.
		api.AssertIsEqual(api.Mul(s.B, api.Sub(s.Role, 1)), 0)
		lv := []frontend.Variable{c.Epoch, i + 1}
		lv = append(lv, g2vars(s.PK)...)
		lv = append(lv, s.Weight, s.Role, c.Policy)
		rosterLeaves[i] = circuitHash(api, 101, lv...)
		total = api.Add(total, api.Mul(s.B, s.Weight))
		// One independent equation per slot. No cross-member product/batch equation.
		if err := sw.PairingCheck(api, []sw.G1Affine{s.Sig, c.HPoint}, []sw.G2Affine{negG2, s.PK}); err != nil {
			return err
		}
		aggSig.AddUnified(api, s.Sig)
		aggPK.P.AddUnified(api, s.PK.P)
		if c.DisableAudit {
			continue
		}
		// Prove Enc under AuditPK with per-slot randomness R.
		var expectedE, shared sw.G1Affine
		expectedE.ScalarMul(api, g1, s.R)
		shared.ScalarMul(api, c.AuditPK, s.R)
		expectedE.AssertIsEqual(api, s.TagE)
		plain := []frontend.Variable{i + 1}
		plain = append(plain, g2vars(s.PK)...)
		plain = append(plain, c.Message, circuitHash(api, 204, g1vars(s.Sig)...))
		for j := range s.TagC {
			maskv := append(g1vars(shared), g1vars(s.TagE)...)
			maskv = append(maskv, c.Message, j)
			api.AssertIsEqual(s.TagC[j], api.Add(plain[j], circuitHash(api, 303, maskv...)))
		}
		th := circuitHash(api, 205, tagVars(*s)...)
		auditLeaves[i] = api.Select(s.B, th, circuitHash(api, 205, 0, i))
	}
	api.AssertIsEqual(root(api, rosterLeaves, 102), c.RosterRoot)
	if !c.DisableAudit {
		api.AssertIsEqual(root(api, auditLeaves, 206), c.AuditRoot)
	}
	api.AssertIsEqual(total, c.RealizedWeight)
	api.AssertIsLessOrEqual(c.Threshold, total)
	aggSig.AssertIsEqual(api, c.AggSig)
	aggPK.P.AssertIsEqual(api, c.AggPK.P)
	return nil
}
