import os, re, sys
hits = [os.path.join(d, f) for r in sys.argv[1:] for d, _, fs in os.walk(r) for f in fs if f.endswith((".js", ".html", ".css", ".go", ".java", ".kt", ".xml", ".json", ".txt"))
        and re.search("[؀-ۿ]", open(os.path.join(d, f), encoding="utf-8", errors="ignore").read())]
print("\n".join(hits))
sys.exit(1 if hits else 0)
