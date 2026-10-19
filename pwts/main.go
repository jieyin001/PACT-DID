package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	N              int     `json:"n"`
	Constraints    int     `json:"constraints"`
	CompileMs      float64 `json:"compile_ms"`
	SetupMs        float64 `json:"setup_ms"`
	ProveMs        float64 `json:"prove_ms"`
	ZKVerifyMs     float64 `json:"zk_verify_ms"`
	NativeVerifyMs float64 `json:"native_verify_ms"`
	FullVerifyMs   float64 `json:"full_verify_ms"`
	PeakRSS        uint64  `json:"peak_rss_bytes"`
	ProofBytes     int     `json:"proof_bytes"`
	PKBytes        int     `json:"pk_bytes"`
	VKBytes        int     `json:"vk_bytes"`
	Status         string  `json:"status"`
	Error          string  `json:"error,omitempty"`
}
type AuditResult struct {
	N                  int     `json:"n"`
	Threshold          int     `json:"threshold"`
	DKGMs              float64 `json:"dkg_ms"`
	OpenMs             float64 `json:"open_ms"`
	RefreshMs          float64 `json:"refresh_ms"`
	PostRefreshOpenMs  float64 `json:"post_refresh_open_ms"`
	HandoverMs         float64 `json:"handover_ms"`
	PostHandoverOpenMs float64 `json:"post_handover_open_ms"`
	Status             string  `json:"status"`
	Error              string  `json:"error,omitempty"`
}

func timed(f func() error) (float64, error) {
	s := time.Now()
	e := f()
	return float64(time.Since(s).Microseconds()) / 1000, e
}
func sizeOf(w interface {
	WriteTo(io.Writer) (int64, error)
}) int {
	var b bytes.Buffer
	w.WriteTo(&b)
	return b.Len()
}

// Native points are retained in Fixture to avoid converting frontend assignments.
func benchmark(n int) Result {
	r := Result{N: n, Status: "failed"}
	f, err := makeFixture(n)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	var ccs constraint.ConstraintSystem
	r.CompileMs, err = timed(func() error {
		var e error
		ccs, e = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &f.Circuit)
		return e
	})
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Constraints = ccs.GetNbConstraints()
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	r.SetupMs, err = timed(func() error { var e error; pk, vk, e = groth16.Setup(ccs); return e })
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.PKBytes = sizeOf(pk)
	r.VKBytes = sizeOf(vk)
	full, err := frontend.NewWitness(&f.Witness, ecc.BW6_761.ScalarField())
	if err != nil {
		r.Error = err.Error()
		return r
	}
	pub, _ := full.Public()
	var proof groth16.Proof
	r.ProveMs, err = timed(func() error { var e error; proof, e = groth16.Prove(ccs, pk, full); return e })
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.ProofBytes = sizeOf(proof)
	r.ZKVerifyMs, err = timed(func() error { return groth16.Verify(proof, vk, pub) })
	if err != nil {
		r.Error = err.Error()
		return r
	}
	// Use retained aggregate points for native check.
	r.NativeVerifyMs, err = timed(func() error { return verifyAggregate(f) })
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.FullVerifyMs = r.ZKVerifyMs + r.NativeVerifyMs
	_, r.PeakRSS = processMemory()
	r.Status = "ok"
	return r
}
func verifyAggregate(f *Fixture) error {
	return verifyAggregateForMessage(f, 555)
}
func verifyAggregateForMessage(f *Fixture, message uint64) error {
	_, _, _, g2 := bls.Generators()
	neg := g2
	neg.Neg(&neg)
	h := messagePoint(message)
	var sig bls.G1Affine
	var pk bls.G2Affine
	for i := range f.Signatures {
		sig = g1add(sig, f.Signatures[i])
		pk = g2add(pk, f.Keys[i])
	}
	ok, err := bls.PairingCheck([]bls.G1Affine{sig, h}, []bls.G2Affine{neg, pk})
	if err != nil || !ok {
		return errors.New("aggregate BLS verification failed")
	}
	return nil
}
func openingParts(s *AuditState, tag AuditTag) ([]OpeningShare, error) {
	parts := make([]OpeningShare, s.Threshold)
	for i := range parts {
		p, err := s.Partial(tag, s.IDs[i])
		if err != nil {
			return nil, err
		}
		parts[i] = p
	}
	return parts, nil
}
func benchmarkAudit(n int) (r AuditResult) {
	r.N, r.Threshold, r.Status = n, n/2+1, "failed"
	var base *AuditState
	var err error
	r.DKGMs, err = timed(func() error { base, err = DKG(n, r.Threshold, 1); return err })
	if err != nil {
		r.Error = err.Error()
		return
	}
	_, _, _, g2 := bls.Generators()
	msg := num(555)
	sk := randomScalar()
	pk := g2mul(g2, sk)
	sig := g1mul(messagePoint(555), sk)
	tag := encryptTag(base.PK, tagPlain(1, pk, msg, sig), msg, randomScalar())
	r.OpenMs, err = timed(func() error {
		p, e := openingParts(base, tag)
		if e != nil {
			return e
		}
		_, e = base.Open(tag, msg, p)
		return e
	})
	if err != nil {
		r.Error = err.Error()
		return
	}
	refreshBase, _ := DKG(n, r.Threshold, 1)
	refreshTag := encryptTag(refreshBase.PK, tagPlain(1, pk, msg, sig), msg, randomScalar())
	var refreshed *AuditState
	r.RefreshMs, err = timed(func() error { refreshed, err = refreshBase.Evolve(n, r.Threshold, false); return err })
	if err != nil {
		r.Error = err.Error()
		return
	}
	r.PostRefreshOpenMs, err = timed(func() error {
		p, e := openingParts(refreshed, refreshTag)
		if e != nil {
			return e
		}
		_, e = refreshed.Open(refreshTag, msg, p)
		return e
	})
	if err != nil {
		r.Error = err.Error()
		return
	}
	handoverBase, _ := DKG(n, r.Threshold, 1)
	handoverTag := encryptTag(handoverBase.PK, tagPlain(1, pk, msg, sig), msg, randomScalar())
	var handed *AuditState
	r.HandoverMs, err = timed(func() error { handed, err = handoverBase.Evolve(n, r.Threshold, true); return err })
	if err != nil {
		r.Error = err.Error()
		return
	}
	r.PostHandoverOpenMs, err = timed(func() error {
		p, e := openingParts(handed, handoverTag)
		if e != nil {
			return e
		}
		_, e = handed.Open(handoverTag, msg, p)
		return e
	})
	if err != nil {
		r.Error = err.Error()
		return
	}
	r.Status = "ok"
	return
}
func writeAudit(out string, sizes []int) {
	rows := make([]AuditResult, 0, len(sizes))
	for _, n := range sizes {
		rows = append(rows, benchmarkAudit(n))
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	_ = os.WriteFile(filepath.Join(out, "audit_results.json"), b, 0644)
	f, _ := os.Create(filepath.Join(out, "audit_results.csv"))
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"n", "threshold", "dkg_ms", "open_ms", "refresh_ms", "post_refresh_open_ms", "handover_ms", "post_handover_open_ms", "status", "error"})
	for _, r := range rows {
		_ = w.Write([]string{strconv.Itoa(r.N), strconv.Itoa(r.Threshold), fmt.Sprint(r.DKGMs), fmt.Sprint(r.OpenMs), fmt.Sprint(r.RefreshMs), fmt.Sprint(r.PostRefreshOpenMs), fmt.Sprint(r.HandoverMs), fmt.Sprint(r.PostHandoverOpenMs), r.Status, r.Error})
	}
	w.Flush()
}
func main() {
	sizes := flag.String("sizes", "4,8,16", "")
	out := flag.String("out", "results", "")
	auditOnly := flag.Bool("audit-only", false, "measure lifecycle operations without rebuilding Rsel")
	serve := flag.Bool("serve-local", false, "loopback reference proof service for the isolated dual-chain testbed")
	flag.Parse()
	if *serve {
		if err := serveLocal(*out); err != nil {
			panic(err)
		}
		return
	}
	os.MkdirAll(*out, 0755)
	var rows []Result
	parsedSizes := make([]int, 0)
	for _, s := range strings.Split(*sizes, ",") {
		n, e := strconv.Atoi(s)
		if e != nil {
			panic(e)
		}
		parsedSizes = append(parsedSizes, n)
		if *auditOnly {
			continue
		}
		fmt.Printf("benchmark n=%d\n", n)
		r := benchmark(n)
		rows = append(rows, r)
		b, _ := json.MarshalIndent(rows, "", "  ")
		os.WriteFile(filepath.Join(*out, "rsel_results.json"), b, 0644)
		if r.Status != "ok" {
			fmt.Println(r.Error)
			break
		}
	}
	if !*auditOnly {
		f, _ := os.Create(filepath.Join(*out, "rsel_results.csv"))
		defer f.Close()
		w := csv.NewWriter(f)
		w.Write([]string{"n", "constraints", "compile_ms", "setup_ms", "prove_ms", "peak_rss_bytes", "zk_verify_ms", "native_verify_ms", "full_verify_ms", "proof_bytes", "pk_bytes", "vk_bytes", "status"})
		for _, r := range rows {
			w.Write([]string{strconv.Itoa(r.N), strconv.Itoa(r.Constraints), fmt.Sprint(r.CompileMs), fmt.Sprint(r.SetupMs), fmt.Sprint(r.ProveMs), fmt.Sprint(r.PeakRSS), fmt.Sprint(r.ZKVerifyMs), fmt.Sprint(r.NativeVerifyMs), fmt.Sprint(r.FullVerifyMs), strconv.Itoa(r.ProofBytes), strconv.Itoa(r.PKBytes), strconv.Itoa(r.VKBytes), r.Status})
		}
		w.Flush()
	}
	writeAudit(*out, parsedSizes)
	fmt.Println("OUTPUT="+*out, "GO=", runtime.Version())
}
