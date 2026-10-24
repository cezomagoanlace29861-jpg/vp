// Adlist merges ad and tracker block lists into one sing-box rule set
// source, which CI compiles and publishes for the apps every day
// (.github/workflows/adblock.yml).
//
//	adlist -allow allow.txt -keep keep.txt -out ads.json list...
//
// A list may be in hosts, plain domain, wildcard (*.example.com) or Adblock
// (||example.com^) form, and every entry blocks the name and the names under
// it. -keep adds names of its own. A name in -allow, or in an Adblock
// exception (@@||example.com^), is never blocked itself; names under it that
// a list names on their own (ads.example.com under an allowed example.com)
// still are, unless they are in -allow too. Names in -keep are always
// blocked.
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
	keep, allow := names{}, names{}
	for _, f := range []struct {
		path string
		into names
	}{{*keepPath, keep}, {*allowPath, allow}} {
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
	src, stats := build(l.block, keep, allow)
	log.Printf("%d names blocked (%d allowed names left out, %d covered by a parent), %d allowed under a blocked name", stats.blocked, stats.allowed, stats.covered, stats.exceptions)
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
	// A comment starts the line or follows a space; any other "#" is an
	// Adblock element rule (example.com##.banner), which blocks nothing.
	line = strings.TrimSpace(strings.ReplaceAll(line, "\t", " "))
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" || line[0] == '!' || line[0] == '[' || strings.Contains(line, "#") {
		return ""
	}
	if strings.HasPrefix(line, "@@") {
		if n := entry(line[2:]); n != "" && !strings.HasPrefix(n, "@@") {
			return "@@" + n
		}
		return ""
	}
	// "||name^" is the name and the names under it; "|name^|" (an exact
	// address) and a trailing "|" are read the same way here, since a
	// block list can only name whole names.
	if rule, ok := strings.CutPrefix(line, "||"); ok || strings.HasPrefix(line, "|") {
		if !ok {
			rule = line[1:]
		}
		rule, opts, _ := strings.Cut(rule, "$")
		if opts != "" && opts != "important" {
			return ""
		}
		n, ok := strings.CutSuffix(strings.TrimSuffix(rule, "|"), "^")
		if !ok || strings.ContainsAny(n, "/*^|:") {
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

// build returns the rule set source: the block list without the allowed
// names, and an inverted rule for allowed names under a blocked one, in
// sing-box's headless rule form.
func build(block, keep, allow names) (map[string]any, buildStats) {
	var st buildStats
	all := names{}
	for _, s := range []names{block, keep} {
		for n := range s {
			if allow[n] && !keep[n] {
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
	var except []string
	for n := range allow {
		if i := strings.IndexByte(n, '.'); !keep[n] && i >= 0 && all.under(n[i+1:]) {
			except = append(except, n)
		}
	}
	sort.Strings(list)
	sort.Strings(except)
	st.blocked, st.exceptions = len(list), len(except)
	rule := map[string]any{"domain_suffix": list}
	if len(except) > 0 {
		rule = map[string]any{"type": "logical", "mode": "and", "rules": []any{
			rule, map[string]any{"domain": except, "invert": true},
		}}
	}
	return map[string]any{"version": 2, "rules": []any{rule}}, st
}
