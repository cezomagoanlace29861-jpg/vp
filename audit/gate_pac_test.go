package engine

// Release gate test (checker only): runs the real PAC file in node with a
// resolver that answers like Iran's (10.10.34.36) and records every lookup.

import (
	"context"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestGatePACNeverResolves(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go servePAC(ctx, "127.0.0.1:18700")
	var body []byte
	for i := 0; i < 50 && body == nil; i++ {
		time.Sleep(100 * time.Millisecond)
		if r, err := http.Get("http://127.0.0.1:" + pacPort("18700") + "/proxy.pac"); err == nil {
			body, _ = io.ReadAll(r.Body)
			r.Body.Close()
		}
	}
	if body == nil {
		t.Fatal("PAC not served")
	}
	js := `let looked=[];
function dnsResolve(h){looked.push(h);return "10.10.34.36"}
function isResolvable(h){looked.push(h);return true}
function myIpAddress(){return "192.168.1.2"}
function isPlainHostName(h){return h.indexOf(".")<0}
function dnsDomainIs(h,d){return h.endsWith(d)}
function shExpMatch(s,p){return new RegExp("^"+p.replace(/\./g,"\\.").replace(/\*/g,".*")+"$").test(s)}
function convert(ip){return ip.split(".").reduce((a,b)=>a*256+(+b),0)}
function isInNet(h,p,m){let ip=/^[0-9.]+$/.test(h)?h:dnsResolve(h);return (convert(ip)&convert(m))==(convert(p)&convert(m))}
` + string(body) + `
const want={"www.youtube.com":"PROXY","twitter.com":"PROXY","digikala.com":"","192.168.1.5":"DIRECT","10.0.0.1":"DIRECT","printer":"DIRECT","8.8.8.8":"PROXY"};
let bad=[];for(const h in want){const r=FindProxyForURL("https://"+h+"/",h);if(want[h]&&!r.startsWith(want[h]))bad.push(h+" -> "+r)}
const names=looked.filter(h=>!/^[0-9.]+$/.test(h));if(names.length)bad.push("resolved names: "+names.join(","));
console.log(bad.length?"BAD "+bad.join("; "):"OK")`
	out, err := exec.Command("node", "-e", js).CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "OK") {
		t.Fatalf("PAC check: %s %v", out, err)
	}
}
