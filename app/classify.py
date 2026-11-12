"""Domain classification: manual rules, downloaded lists, then keyword heuristics.
Results are cached in memory; the cache is cleared whenever lists or rules change."""
import threading
import time

ACTION_RANK = {"ignore": 0, "log": 1, "alert": 2, "block": 3, "allow": -1}
SLD = {"co", "com", "net", "org", "gov", "edu", "ac", "gc", "qc", "on"}
SEX_PREFIX_EXCEPT = ("sexton", "sextant", "sextet", "sextuple", "sexagen", "sexism", "sexist", "sexless",
                     "sexolog", "sexual", "sexed", "sexsomn")
SEX_SUFFIX_EXCEPT = ("essex", "sussex", "middlesex", "wessex", "unisex")


class Classifier:
    def __init__(self, store):
        self.store = store
        self.conn = store.reader()
        self.lock = threading.Lock()
        self.cache = {}
        self.cache_ttl = 600
        self.meta = {}
        self.keywords = []
        self.reload()

    def close(self):
        with self.lock:
            try:
                self.conn.close()
            except Exception:
                pass

    def reload(self):
        meta = {c["key"]: c for c in self.store.categories()}
        kws = self.store.get_setting("keywords", []) or []
        with self.lock:
            self.meta = meta
            self.keywords = [k.strip().lower() for k in kws if k and k.strip()]
            self.cache.clear()

    @staticmethod
    def candidates(name):
        parts = name.split(".")
        cands = [".".join(parts[i:]) for i in range(len(parts) - 1)]
        return cands or [name]

    def _make(self, key, source, matched):
        m = self.meta.get(key) or {"label": key, "action": "alert", "mode": "ip", "severity": 2}
        return {"category": key, "label": m["label"], "action": m["action"], "mode": m["mode"],
                "severity": m["severity"], "source": source, "matched": matched}

    def classify(self, name):
        """None when nothing matches, else a dict with category/action/mode/label/source/matched.
        action 'allow' means an allow rule matched."""
        if not name:
            return None
        t = time.time()
        with self.lock:
            hit = self.cache.get(name)
        if hit and hit[1] > t:
            return hit[0]
        res = self._lookup(name)
        with self.lock:
            if len(self.cache) > 20000:
                self.cache.clear()
            self.cache[name] = (res, t + self.cache_ttl)
        return res

    def _lookup(self, name):
        cands = self.candidates(name)
        with self.lock:
            for c in cands:
                r = self.conn.execute("SELECT category FROM rules WHERE domain=?", (c,)).fetchone()
                if r:
                    if r[0] == "allow":
                        return {"category": "", "label": "Autorisé (règle manuelle)", "action": "allow", "mode": "ip",
                                "severity": 0, "source": "rule", "matched": c}
                    return self._make(r[0], "rule", c)
            for c in cands:
                rows = self.conn.execute("SELECT category FROM listed WHERE domain=?", (c,)).fetchall()
                if rows:
                    return max((self._make(r[0], "list", c) for r in rows),
                               key=lambda m: (ACTION_RANK.get(m["action"], 0), m["severity"]))
        kw = self._keyword(name)
        if kw:
            return self._make("keyword", "keyword", kw)
        return None

    def _keyword(self, name):
        parts = name.split(".")
        if len(parts) < 2 or not self.keywords:
            return ""
        labels = parts[:-1]
        if len(parts) >= 3 and parts[-2] in SLD and len(parts[-1]) == 2:
            labels = parts[:-2]
        for label in labels:
            for kw in self.keywords:
                if kw == "sex":
                    if self._sex(label):
                        return label
                elif kw in label:
                    return label
        return ""

    @staticmethod
    def _sex(label):
        if label == "sex":
            return True
        if label.startswith("sex") and not label.startswith(SEX_PREFIX_EXCEPT):
            return True
        if label.endswith("sex") and not label.endswith(SEX_SUFFIX_EXCEPT):
            return True
        return False
