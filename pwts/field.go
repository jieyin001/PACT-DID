package main

import (
	"crypto/sha256"
	"encoding/binary"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	sf "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	ff "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"math/big"
)

type F = ff.Element
type S = sf.Element

func num(v uint64) F                                            { var x F; x.SetUint64(v); return x }
func integer(x interface{ BigInt(*big.Int) *big.Int }) *big.Int { return x.BigInt(new(big.Int)) }
func coord(x interface{ BigInt(*big.Int) *big.Int }) F          { var r F; r.SetBigInt(integer(x)); return r }
func randomScalar() S {
	for {
		var s S
		if _, e := s.SetRandom(); e != nil {
			panic(e)
		}
		if !s.IsZero() {
			return s
		}
	}
}
func hashF(domain uint64, values ...F) F {
	h := mimc.NewMiMC()
	d := num(domain)
	b := d.Bytes()
	h.Write(b[:])
	for _, v := range values {
		b = v.Bytes()
		h.Write(b[:])
	}
	var r F
	r.SetBytes(h.Sum(nil))
	return r
}
func g1Fields(p bls.G1Affine) []F { return []F{coord(&p.X), coord(&p.Y)} }
func g2Fields(p bls.G2Affine) []F {
	return []F{coord(&p.X.A0), coord(&p.X.A1), coord(&p.Y.A0), coord(&p.Y.A1)}
}
func shaScalar(domain string, epoch uint64, id int, points ...bls.G1Affine) S {
	h := sha256.New()
	h.Write([]byte(domain))
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], epoch)
	binary.BigEndian.PutUint64(b[8:], uint64(id))
	h.Write(b[:])
	for _, p := range points {
		v := p.Bytes()
		h.Write(v[:])
	}
	var s S
	s.SetBytes(h.Sum(nil))
	return s
}
func g1mul(p bls.G1Affine, s S) bls.G1Affine {
	var q bls.G1Affine
	q.ScalarMultiplication(&p, integer(&s))
	return q
}
func g1add(p, q bls.G1Affine) bls.G1Affine { var r bls.G1Affine; r.Add(&p, &q); return r }
func g2mul(p bls.G2Affine, s S) bls.G2Affine {
	var q bls.G2Affine
	q.ScalarMultiplication(&p, integer(&s))
	return q
}
func g2add(p, q bls.G2Affine) bls.G2Affine                              { var r bls.G2Affine; r.Add(&p, &q); return r }
func blsGenerators() (bls.G1Jac, bls.G2Jac, bls.G1Affine, bls.G2Affine) { return bls.Generators() }
func messagePoint(message uint64) bls.G1Affine {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], message)
	p, err := bls.HashToG1(encoded[:], []byte("EQUIDID_BLS12377G1_XMD:SHA-256_SSWU_RO_V1"))
	if err != nil {
		panic(err)
	}
	return p
}
func polyEval(coeff []S, id int) S {
	var x, r S
	x.SetUint64(uint64(id))
	for j := len(coeff) - 1; j >= 0; j-- {
		r.Mul(&r, &x)
		r.Add(&r, &coeff[j])
	}
	return r
}
func commitEval(coeff []bls.G1Affine, id int) bls.G1Affine {
	var x, pow S
	x.SetUint64(uint64(id))
	pow.SetOne()
	var r bls.G1Affine
	for _, c := range coeff {
		r = g1add(r, g1mul(c, pow))
		pow.Mul(&pow, &x)
	}
	return r
}
func lagrange(ids []int, id int) S {
	var r, x S
	r.SetOne()
	x.SetUint64(uint64(id))
	for _, j := range ids {
		if j == id {
			continue
		}
		var y, d, inv S
		y.SetUint64(uint64(j))
		d.Sub(&y, &x)
		inv.Inverse(&d)
		r.Mul(&r, &y)
		r.Mul(&r, &inv)
	}
	return r
}
