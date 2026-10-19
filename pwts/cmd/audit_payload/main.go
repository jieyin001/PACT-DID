// Report actual primitive encoding sizes used by the audit reference.
package main

import (
 "encoding/json"
 "os"
 bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
 sf "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
 ff "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)
func main(){
 _,_,g,_:=bls.Generators();var inf bls.G1Affine;var s sf.Element;var f ff.Element
 sizes:=map[string]int{"g1_compressed":len(g.Bytes()),"g1_identity_compressed":len(inf.Bytes()),
 "share_scalar":len(s.Bytes()),"tag_field":len(f.Bytes()),"epoch_u64":8,"auditor_id_u64":8}
 if err:=json.NewEncoder(os.Stdout).Encode(sizes);err!=nil{panic(err)}
}
