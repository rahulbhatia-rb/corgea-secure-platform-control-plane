package main
import (
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "github.com/rahulbhatia-rb/corgea-secure-platform-control-plane/internal/policy"
)
func main(){
 path:=flag.String("contract","","platform contract JSON"); flag.Parse()
 if *path=="" { fmt.Fprintln(os.Stderr,"usage: platformgate -contract <file>"); os.Exit(2) }
 raw,err:=os.ReadFile(*path); if err!=nil { panic(err) }
 var c policy.Contract; if err:=json.Unmarshal(raw,&c); err!=nil { panic(err) }
 r:=policy.Evaluate(c); out,_:=json.MarshalIndent(r,"","  "); fmt.Println(string(out))
 if !r.Allowed { os.Exit(1) }
}
