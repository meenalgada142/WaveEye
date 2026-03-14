# ================================================================
#                       ALIAS ENGINE MODULE
# ================================================================
import re
class AliasEngine:
    def __init__(self):
        self.alias_of = {}
        self.aliases_to = {}

    def add_alias(self, a, b):
        if not a or not b or a == b:
            return
        if self.would_form_cycle(a, b):
            return
        prev = self.alias_of.get(a)
        if prev:
            self.aliases_to.get(prev, set()).discard(a)
        self.alias_of[a] = b
        self.aliases_to.setdefault(b, set()).add(a)

    def would_form_cycle(self, a, b):
        visited = set()
        cur = b
        while cur in self.alias_of:
            if cur == a or cur in visited:
                return True
            visited.add(cur)
            cur = self.alias_of[cur]
        return False

    def resolve(self, sig):
        visited = set()
        cur = sig
        while cur in self.alias_of:
            nxt = self.alias_of[cur]
            if nxt in visited:
                break
            visited.add(cur)
            cur = nxt
        return cur

    def chain(self, sig):
        out = [sig]
        visited = set()
        cur = sig
        while cur in self.alias_of:
            nxt = self.alias_of[cur]
            if nxt in visited:
                out.append(nxt)
                out.append("(loop detected)")
                return out
            visited.add(cur)
            out.append(nxt)
            cur = nxt
        return out

    def downstream(self, sig):
        result = set()
        stack = [sig]
        while stack:
            root = stack.pop()
            for a in self.aliases_to.get(root, set()):
                if a not in result:
                    result.add(a)
                    stack.append(a)
        return result

    def collapse_all(self):
        all_signals = set(self.alias_of.keys()) | set(self.aliases_to.keys())
        return {s: self.resolve(s) for s in all_signals}
    def detect_pure_assign_aliases(self, drivers):
        """
        Detect aliases ONLY when lhs = rhs is a pure signal-to-signal assignment.
        No heuristics. No suffix logic. No prefix rules.
        Only strict:  A = B  or  assign A = B.
        """
        sig_re = re.compile(r"^[a-zA-Z_]\w*$")

        for lhs, drv_list in drivers.items():
            for d in drv_list:
                rhs = d.get("rhs", "").strip()

                # RHS must be a pure signal name (not expression)
                if not sig_re.fullmatch(rhs):
                    continue

                # Only allow alias when both LHS and RHS are simple signals
                if not sig_re.fullmatch(lhs):
                    continue

                # Add alias: lhs -> rhs
                self.add_alias(lhs, rhs)