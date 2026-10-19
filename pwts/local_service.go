package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	sw "github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

func requestFixture(base *Fixture, digest []byte) (*Fixture, error) {
	return requestFixturePrepared(base, digest, prepareAudit(base.Audit, len(base.Keys)))
}

func requestFixturePrepared(base *Fixture, digest []byte, prepared *auditPrecompute) (*Fixture, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes")
	}
	f := *base
	f.Witness.Slots = append([]Slot(nil), base.Witness.Slots...)
	f.Tags = make([]AuditTag, len(base.Keys))
	f.Signatures = make([]bls.G1Affine, len(base.Keys))
	var msg F
	msg.SetBytes(digest)
	h, err := bls.HashToG1(digest, []byte("EQUIDID_REQUEST_BLS12377G1_XMD:SHA-256_SSWU_RO_V1"))
	if err != nil {
		return nil, err
	}
	var aggregate bls.G1Affine
	rs, es, shared, err := prepared.take(base.Audit, len(base.Keys))
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range rs {
			rs[i].SetZero()
		}
	}()
	leaves := make([]F, len(base.Keys))
	for i := range base.Keys {
		sig := g1mul(h, base.Secrets[i])
		r := rs[i]
		plain := tagPlain(i+1, base.Keys[i], msg, sig)
		tag := AuditTag{E: es[i]}
		for j := range tag.C {
			m := mask(shared[i], es[i], msg, j)
			tag.C[j].Add(&plain[j], &m)
		}
		f.Signatures[i] = sig
		f.Tags[i] = tag
		leaves[i] = tagHash(tag)
		f.Witness.Slots[i].Sig = sw.NewG1Affine(sig)
		f.Witness.Slots[i].R = integer(&r)
		f.Witness.Slots[i].TagE = sw.NewG1Affine(tag.E)
		for j := range tag.C {
			f.Witness.Slots[i].TagC[j] = integer(&tag.C[j])
		}
		aggregate = g1add(aggregate, sig)
	}
	for len(leaves) > 1 {
		next := make([]F, len(leaves)/2)
		for i := range next {
			next[i] = hashF(206, leaves[2*i], leaves[2*i+1])
		}
		leaves = next
	}
	f.Witness.Message = integer(&msg)
	f.Witness.HPoint = sw.NewG1Affine(h)
	f.Witness.AggSig = sw.NewG1Affine(aggregate)
	f.Witness.AuditRoot = integer(&leaves[0])
	return &f, nil
}

type localCertificate struct {
	Payload string `json:"payload"`
	Proof   []byte `json:"proof"`
	Public  []byte `json:"public"`
	Session string `json:"session"`
}

func serveLocal(out string) error {
	if err := os.MkdirAll(out, 0700); err != nil {
		return err
	}
	base, err := makeFixture(4)
	if err != nil {
		return err
	}
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &base.Circuit)
	if err != nil {
		return err
	}
	fmt.Println("Setting up local 4-member proof service (excluded from request timing)")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return err
	}
	var vkbytes bytes.Buffer
	if _, err = vk.WriteTo(&vkbytes); err != nil {
		return err
	}
	sessionHash := sha256.Sum256(vkbytes.Bytes())
	session := hex.EncodeToString(sessionHash[:])
	var rr F
	rr.SetBigInt(base.Witness.RosterRoot.(*big.Int))
	expected := ExpectedRSelContext{Epoch: 1, Policy: 77, Threshold: 4006, RosterRoot: rr, AuditPK: base.Audit.PK}
	var lock sync.Mutex
	// Bounded one-use inventory. Refill cost is offline, not eliminated. A
	// depleted pool blocks and that wait is included in construction_ms.
	pool := make(chan *auditPrecompute, 8)
	for i := 0; i < cap(pool); i++ {
		pool <- prepareAudit(base.Audit, len(base.Keys))
	}
	go func() {
		for {
			pool <- prepareAudit(base.Audit, len(base.Keys))
		}
	}()
	write := func(w http.ResponseWriter, code int, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(value)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"ready": true, "members": 4, "session": session, "constraints": ccs.GetNbConstraints(), "scope": "local Rsel authorization; no chain finality validation inside prover"})
	})
	mux.HandleFunc("/prove", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			write(w, 405, map[string]string{"error": "POST required"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Payload) == 0 {
			write(w, 400, map[string]string{"error": "invalid payload"})
			return
		}
		lock.Lock()
		defer lock.Unlock()
		start := time.Now()
		digest := sha256.Sum256([]byte(req.Payload))
		prepared := <-pool
		precomputeEnd := time.Now()
		f, err := requestFixturePrepared(base, digest[:], prepared)
		if err != nil {
			write(w, 500, map[string]string{"error": err.Error()})
			return
		}
		fw, err := frontend.NewWitness(&f.Witness, ecc.BW6_761.ScalarField())
		if err != nil {
			write(w, 500, map[string]string{"error": err.Error()})
			return
		}
		witnessEnd := time.Now()
		proof, err := groth16.Prove(ccs, pk, fw)
		proofEnd := time.Now()
		if err != nil {
			write(w, 500, map[string]string{"error": err.Error()})
			return
		}
		pub, err := fw.Public()
		if err != nil {
			write(w, 500, map[string]string{"error": err.Error()})
			return
		}
		var pb, ub bytes.Buffer
		proof.WriteTo(&pb)
		pub.WriteTo(&ub)
		cert := localCertificate{Payload: req.Payload, Proof: pb.Bytes(), Public: ub.Bytes(), Session: session}
		encoded, err := json.Marshal(cert)
		if err != nil {
			write(w, 500, map[string]string{"error": err.Error()})
			return
		}
		tags, err := json.Marshal(f.Tags)
		if err != nil {
			write(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err = os.WriteFile(filepath.Join(out, hex.EncodeToString(digest[:])+".audit.json"), tags, 0600); err != nil {
			write(w, 500, map[string]string{"error": err.Error()})
			return
		}
		write(w, 200, map[string]any{"certificate": cert, "certificate_bytes": len(encoded), "audit_json_bytes": len(tags), "audit_binary_bytes": 4 * 384, "construction_ms": float64(time.Since(start).Nanoseconds()) / 1e6,
			"precompute_wait_ms":           float64(precomputeEnd.Sub(start).Nanoseconds()) / 1e6,
			"witness_ms":                   float64(witnessEnd.Sub(precomputeEnd).Nanoseconds()) / 1e6,
			"groth16_prove_ms":             float64(proofEnd.Sub(witnessEnd).Nanoseconds()) / 1e6,
			"serialization_audit_store_ms": float64(time.Since(proofEnd).Nanoseconds()) / 1e6})
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			write(w, 405, map[string]string{"error": "POST required"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var cert localCertificate
		if err := json.NewDecoder(r.Body).Decode(&cert); err != nil || cert.Session != session {
			write(w, 400, map[string]string{"error": "invalid certificate/session"})
			return
		}
		start := time.Now()
		digest := sha256.Sum256([]byte(cert.Payload))
		ctx := expected
		ctx.RequestDigest = digest[:]
		if err := VerifyReferenceRSel(cert.Proof, cert.Public, vk, ctx); err != nil {
			write(w, 400, map[string]any{"verified": false, "error": err.Error()})
			return
		}
		write(w, 200, map[string]any{"verified": true, "verification_ms": float64(time.Since(start).Nanoseconds()) / 1e6})
	})
	fmt.Println("READY http://127.0.0.1:18081 session=" + session)
	return (&http.Server{Addr: "127.0.0.1:18081", Handler: mux, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe()
}
