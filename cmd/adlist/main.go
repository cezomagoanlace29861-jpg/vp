// Adlist merges ad and tracker block lists into one sing-box rule set
// source, which CI compiles and publishes for the apps every day
// (.github/workflows/adblock.yml).
//
//	adlist -allow allow.txt -local local.txt -keep keep.txt -out ads.json list...
//
// A list may be in hosts, plain domain, wildcard (*.example.com) or Adblock
// (||example.com^) form, and every entry blocks the name and the names under
// it. -keep adds names of its own. Nothing is blocked at or under a name in
// -allow, an Adblock exception (@@||example.com^) or -local (the region's
// own sites, which the lists do not know and often break), except names at
// or under -keep: the region's own ad networks.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("adlist: ")
	allowPath := flag.String("allow", "", "names never blocked")
	localPath := flag.String("local", "", "the region's own sites, never blocked unless in -keep")
	keepPath := flag.String("keep", "", "names always blocked")
	out := flag.String("out", "ads.json", "rule set source to write")
	min := flag.Int("min", 0, "fail when fewer names than this are blocked")
	flag.Parse()

	var l lists
	for _, p := range flag.Args() {
		before := len(l.block)
		if err := readFile(p, func(r io.Reader) { l.read(r, true) }); err != nil {
			log.Fatal(err)
		}
		log.Printf("%s: %d names", p, len(l.block)-before)
	}
	keep, allow, local := names{}, names{}, names{}
	for _, f := range []struct {
		path string
		into names
	}{{*keepPath, keep}, {*allowPath, allow}, {*localPath, local}} {
		if f.path == "" {
			continue
		}
		var one lists
		if err := readFile(f.path, func(r io.Reader) { one.read(r, false) }); err != nil {
			log.Fatal(err)
		}
		for n := range one.block {
			f.into[n] = true
		}
	}
	for n := range l.allow {
		allow[n] = true
	}
	src, stats := build(l.block, keep, allow, local)
	log.Printf("%d names blocked (%d under allowed names left out, %d covered by a parent), %d allowed", stats.blocked, stats.allowed, stats.covered, stats.exceptions)
	if stats.blocked < *min {
		log.Fatalf("only %d names; a list probably failed to download", stats.blocked)
	}
	b, _ := json.Marshal(src)
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

func readFile(path string, read func(io.Reader)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	read(f)
	return nil
}

type names map[string]bool

// under reports whether n is a name in s or under one.
func (s names) under(n string) bool {
	for {
		if s[n] {
			return true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return false
		}
		n = n[i+1:]
	}
}

type lists struct {
	block, allow names
}

var nameRe = regexp.MustCompile(`^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)

// read adds a list's entries. Adblock exceptions go to allow; in a plain
// file (lists false) they are read as names too.
func (l *lists) read(r io.Reader, lists bool) {
	if l.block == nil {
		l.block, l.allow = names{}, names{}
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		into, n := l.block, entry(sc.Text())
		if strings.HasPrefix(n, "@@") {
			if !lists {
				continue
			}
			into, n = l.allow, entry(n[2:])
		}
		if n != "" && nameRe.MatchString(n) {
			into[n] = true
		}
	}
}

// entry returns the name a list line names, or "" when it names none (a
// comment, or an Adblock rule that is not a whole name). An exception keeps
// its "@@" in front.
func entry(line string) string {
	line = strings.TrimSpace(line)
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" || line[0] == '!' || line[0] == '[' {
		return ""
	}
	if strings.HasPrefix(line, "@@") {
		if n := entry(line[2:]); n != "" && !strings.HasPrefix(n, "@@") {
			return "@@" + n
		}
		return ""
	}
	if strings.HasPrefix(line, "||") {
		rule, opts, _ := strings.Cut(line[2:], "$")
		if opts != "" && opts != "important" {
			return ""
		}
		n, ok := strings.CutSuffix(rule, "^")
		if !ok || strings.ContainsAny(n, "/*^|") {
			return ""
		}
		return clean(n)
	}
	if strings.ContainsAny(line, "|^$/") {
		return ""
	}
	if f := strings.Fields(line); len(f) >= 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1" || f[0] == "::" || f[0] == "::1") {
		line = f[1]
	} else if len(f) != 1 {
		return ""
	}
	return clean(strings.TrimPrefix(strings.TrimPrefix(line, "*."), "."))
}

func clean(n string) string {
	return strings.TrimSuffix(strings.ToLower(n), ".")
}

type buildStats struct {
	blocked, allowed, covered, exceptions int
}

// build returns the rule set source: the block list, with the allowed names
// taken out where they can be (and by an inverted rule where they cannot,
// under a blocked parent), in sing-box's headless rule form.
func build(block, keep, allow, local names) (map[string]any, buildStats) {
	var st buildStats
	exempt := names{}
	for _, s := range []names{allow, local} {
		for n := range s {
			if !keep.under(n) {
				exempt[n] = true
			}
		}
	}
	all := names{}
	for _, s := range []names{block, keep} {
		for n := range s {
			if exempt.under(n) && !keep.under(n) {
				st.allowed++
				continue
			}
			all[n] = true
		}
	}
	var list []string
	for n := range all {
		if i := strings.IndexByte(n, '.'); i >= 0 && all.under(n[i+1:]) {
			st.covered++
			continue
		}
		list = append(list, n)
	}
	// Only exceptions under a blocked name need the inverted rule.
	var except []string
	for n := range exempt {
		if i := strings.IndexByte(n, '.'); i >= 0 && all.under(n[i+1:]) {
			except = append(except, n)
		}
	}
	sort.Strings(list)
	sort.Strings(except)
	st.blocked, st.exceptions = len(list), len(except)
	rule := map[string]any{"domain_suffix": list}
	if len(except) > 0 {
		rule = map[string]any{"type": "logical", "mode": "and", "rules": []any{
			rule, map[string]any{"domain_suffix": except, "invert": true},
		}}
	}
	return map[string]any{"version": 2, "rules": []any{rule}}, st
}

