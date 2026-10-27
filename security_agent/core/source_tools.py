"""Bounded read-only access to a frozen source view, independent of the SDK."""
import json
from security_agent.core.storage import digest, now


def numbered(source, start=1):
    return "\n".join(f"{i}: {line}" for i, line in enumerate(source.splitlines(), start))


class SourceAccess:
    def __init__(self, sources, target, max_calls, max_bytes, journal, *, scope=None):
        self.sources = sources
        self.target = target
        self.scope = scope
        self.max_calls, self.max_bytes = max_calls, max_bytes
        self.calls = 0
        self.bytes = len(scoped_source(sources[target], scope)[0].encode())
        self.exhausted = self.bytes > max_bytes
        self.journal = journal

    def _record(self, name, request, response):
        self.calls += 1
        if self.calls > self.max_calls:
            self.exhausted = True
            response = {"error": "tool call budget exhausted"}
        else:
            size = len(json.dumps(response, ensure_ascii=False).encode())
            if self.bytes + size > self.max_bytes:
                self.exhausted = True
                response = {"error": "source response byte budget exhausted"}
            else:
                self.bytes += size
        with self.journal.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"tool": name, "request": request, "response": response,
                                     "timestamp": now(), "calls": self.calls,
                                     "response_bytes_used": self.bytes}, ensure_ascii=True) + "\n")
            handle.flush()
        return response

    def read(self, file, start=1, end=None):
        if file not in self.sources:
            response = {"error": "file is not in the frozen C/C++ source view"}
        elif file == self.target and self.scope is None and start == 1 and end is None:
            response = {"file": file, "already_provided": True,
                        "instruction": "The complete numbered target is in target_source; use it directly."}
        else:
            source = self.sources[file]
            lines = source.splitlines()
            stop = len(lines) if end is None else end
            if type(start) is not int or type(stop) is not int or not 1 <= start <= stop <= len(lines):
                response = {"error": "invalid inclusive line range"}
            else:
                response = {"file": file, "source": numbered("\n".join(lines[start-1:stop]), start),
                            "sha256": digest(source.encode()), "start": start, "end": stop,
                            "total_lines": len(lines)}
        return self._record("read_source", {"file": file, "start": start, "end": end}, response)

    def search(self, text):
        if not isinstance(text, str) or not text or len(text) > 200:
            return self._record("search_source", {"text": text}, {"error": "use a literal of 1..200 characters"})
        hits, count = [], 0
        for file, source in self.sources.items():
            for number, line in enumerate(source.splitlines(), 1):
                if text in line:
                    count += 1
                    if len(hits) < 100:
                        hits.append({"file": file, "line": number, "text": line})
        return self._record("search_source", {"text": text},
                            {"hits": hits, "total_matches": count, "truncated": count > len(hits)})

def scoped_source(source, scope=None):
    if not scope:
        return source, 1
    return '\n'.join(source.splitlines()[scope['start']-1:scope['end']]), scope['start']
