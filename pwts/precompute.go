package main

import (
	"fmt"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"sync"
)

// One-use, in-memory material. Never persist or reuse after errors. Message
// masks remain online; this only moves rG and rPK out of the request path.
type auditPrecompute struct {
	mu        sync.Mutex
	used      bool
	epoch     uint64
	pk        bls.G1Affine
	r         []S
	e, shared []bls.G1Affine
}

func prepareAudit(a *AuditState, n int) *auditPrecompute {
	p := &auditPrecompute{epoch: a.Epoch, pk: a.PK, r: make([]S, n), e: make([]bls.G1Affine, n), shared: make([]bls.G1Affine, n)}
	for i := range p.r {
		p.r[i] = randomScalar()
		p.e[i] = g1mul(generator1(), p.r[i])
		p.shared[i] = g1mul(a.PK, p.r[i])
	}
	return p
}

func (p *auditPrecompute) take(a *AuditState, n int) ([]S, []bls.G1Affine, []bls.G1Affine, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		return nil, nil, nil, fmt.Errorf("precomputation already consumed")
	}
	p.used = true
	r, e, s := p.r, p.e, p.shared
	p.r = nil
	p.e = nil
	p.shared = nil
	if a.Retired || a.Epoch != p.epoch || !a.PK.Equal(&p.pk) || len(r) != n {
		return nil, nil, nil, fmt.Errorf("stale precomputation context")
	}
	return r, e, s, nil
}
