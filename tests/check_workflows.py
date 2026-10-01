#!/usr/bin/env python3
"""Checks the GitHub Actions workflows before GitHub does (standard library only).

GitHub rejects a workflow whose YAML does not parse, and says so only when the workflow is
triggered -- for release.yml, on the tag push that was supposed to publish. The known trap is a
plain scalar containing ": " (`run: pip install --only-binary=:all: -r x` is a YAML error:
"mapping values are not allowed here"); every text-based check of a workflow passes it.

So this reads each workflow with a strict reader for the subset of YAML the workflows use --
block mappings and sequences, plain / quoted / block scalars, one-line flow sequences -- and
rejects everything outside it, including whatever a real parser would accept but that this
one cannot vouch for (a plain scalar continued on the next line, anchors, tags). The reader
first proves itself on documents it must accept and documents it must reject.

Then the invariants of these workflows:
  * the workflow directory holds exactly ci.yml and release.yml (an empty traversal never passes);
  * every `uses:` is pinned to a 40-hex commit with a `# vX.Y.Z` comment;
  * SDK_REPO / SDK_REF are the same in both files, SDK_REF a 40-hex commit;
  * release.yml: the SDK_REF guard runs before any checkout, the secret is named exactly once,
    and pip installs with --require-hashes --only-binary=:all:.

Usage: check_workflows.py <.github/workflows directory>
"""

import os
import re
import sys

EXPECTED_FILES = ["ci.yml", "release.yml"]
KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
BLOCK_HEADER_RE = re.compile(r"^[|>]([+-]?[1-9]?|[1-9][+-])$")


class YamlError(Exception):
    pass


def strip_comment(text):
    """Text up to an unquoted ' #' (or a '#' at the start)."""
    quote = None
    i = 0
    while i < len(text):
        c = text[i]
        if quote == "'":
            if c == "'":
                if i + 1 < len(text) and text[i + 1] == "'":
                    i += 2
                    continue
                quote = None
        elif quote == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                quote = None
        else:
            if c == "#" and (i == 0 or text[i - 1] in " \t"):
                return text[:i].rstrip()
            if c in "'\"" and (i == 0 or text[i - 1] in " \t[{,:"):
                quote = c
        i += 1
    return text.rstrip()


def check_quoted(v, where):
    q = v[0]
    i = 1
    while i < len(v):
        c = v[i]
        if q == "'" and c == "'":
            if i + 1 < len(v) and v[i + 1] == "'":
                i += 2
                continue
            break
        if q == '"' and c == "\\":
            i += 2
            continue
        if q == '"' and c == '"':
            break
        i += 1
    else:
        raise YamlError("%s: unterminated quoted scalar: %s" % (where, v))
    if v[i + 1:].strip():
        raise YamlError("%s: text after a quoted scalar: %s" % (where, v))


def check_plain(v, where, flow=False):
    if v[0] in "*&!%@`":
        raise YamlError("%s: a scalar may not start with %r here: %s" % (where, v[0], v))
    if v[0] in "-?:" and (len(v) == 1 or v[1] == " "):
        raise YamlError("%s: a plain scalar may not start with %r: %s" % (where, v[:2], v))
    if ": " in v or v.endswith(":"):
        raise YamlError("%s: plain scalar contains ': ' (quote it or use a block scalar `|`): %s" % (where, v))
    if flow and any(c in v for c in ",[]{}"):
        raise YamlError("%s: flow indicator inside a flow scalar: %s" % (where, v))


def check_flow_seq(v, where):
    if not v.endswith("]"):
        raise YamlError("%s: a flow sequence must close on its line: %s" % (where, v))
    inner = v[1:-1].strip()
    if not inner:
        return
    items, cur, quote = [], "", None
    for c in inner:
        if quote:
            cur += c
            if c == quote:
                quote = None
            continue
        if c in "'\"" and not cur.strip():
            quote = c
        if c == ",":
            items.append(cur.strip())
            cur = ""
            continue
        if c in "[]{}":
            raise YamlError("%s: nested flow collections are not supported: %s" % (where, v))
        cur += c
    if quote:
        raise YamlError("%s: unterminated quote in a flow sequence: %s" % (where, v))
    items.append(cur.strip())
    for it in items:
        if not it:
            raise YamlError("%s: empty item in a flow sequence: %s" % (where, v))
        if it[0] in "'\"":
            check_quoted(it, where)
        else:
            check_plain(it, where, flow=True)


def check_value(v, where):
    """Checks a scalar value on a key or sequence line; returns True if it opens a block scalar."""
    if not v:
        return False
    if v[0] in "|>":
        if not BLOCK_HEADER_RE.match(v):
            raise YamlError("%s: bad block scalar header: %s" % (where, v))
        return True
    if v[0] in "'\"":
        check_quoted(v, where)
    elif v[0] == "[":
        check_flow_seq(v, where)
    elif v[0] == "{":
        raise YamlError("%s: flow mappings are not supported: %s" % (where, v))
    else:
        check_plain(v, where)
    return False


def split_key(text):
    """'key: value' / 'key:' -> (key, value); None when the line is not a mapping entry."""
    m = re.match(r"^([^\s'\"#][^:]*?|'[^']*'|\"[^\"]*\"):(?: (.*))?$", text)
    if not m:
        return None
    return m.group(1), (m.group(2) or "").strip()


def parse(text, name="<doc>"):
    """Raises YamlError at the first construct outside the supported subset."""
    if text.startswith("\ufeff"):
        raise YamlError("%s: starts with a BOM" % name)
    block_parent = None  # indent of the line that opened a block scalar
    mappings = []        # stack of (indent, set of keys)
    for n, raw in enumerate(text.split("\n"), 1):
        where = "%s:%d" % (name, n)
        line = raw.rstrip("\r")
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise YamlError("%s: tab in indentation" % where)
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if block_parent is not None:
            if not stripped or indent > block_parent:
                continue
            block_parent = None
        if not stripped or stripped.startswith("#"):
            continue
        if indent == 0 and stripped in ("---", "..."):
            continue
        content = strip_comment(line[indent:])
        col = indent
        # "- " items, possibly nested on one line ("- - x" is not used: reject it).
        seq_item = False
        if content == "-" or content.startswith("- "):
            seq_item = True
            content = content[1:].lstrip(" ")
            col = indent + (len(line[indent:]) - len(line[indent:].lstrip("- ")))
            if content.startswith("- ") or content == "-":
                raise YamlError("%s: nested sequence on one line" % where)
        while mappings and mappings[-1][0] > col:
            mappings.pop()
        if seq_item:
            while mappings and mappings[-1][0] >= col:
                mappings.pop()
        if not content:
            continue
        kv = split_key(content)
        if kv is not None:
            key, value = kv
            if key[0] not in "'\"" and not KEY_RE.match(key):
                raise YamlError("%s: unsupported mapping key %r" % (where, key))
            if not mappings or mappings[-1][0] < col:
                mappings.append((col, set()))
            elif mappings[-1][0] == col and key in mappings[-1][1]:
                raise YamlError("%s: duplicate key %r" % (where, key))
            mappings[-1][1].add(key)
            if check_value(value, where):
                block_parent = col  # its lines are indented deeper than the key
        else:
            if not seq_item:
                raise YamlError("%s: neither a mapping entry nor a sequence item "
                                "(a plain scalar continued on another line?): %s" % (where, stripped))
            if check_value(content, where):
                block_parent = indent
    return True


# ---- The reader proves itself first ------------------------------------------------------

GOOD = """name: X
on:
  push:
    tags: ['v*']
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  a:
    runs-on: windows-2022
    env:
      URL: "http://x/y: z"
    steps:
      - uses: o/r@0123456789abcdef0123456789abcdef01234567  # v1.2.3
        with:
          path: pkg/
      - name: Block
        run: |
          pip install --only-binary=:all: -r x
          echo "a: b"

          echo after a blank line
      - name: Plain with a colon not followed by a space
        run: echo a:b http://x
      - run: echo ${{ github.ref }}  # a comment
"""

BAD = {
    "plain with ': '": "a:\n  run: pip install --only-binary=:all: -r x\n",
    "plain ending in ':'": "a:\n  run: pip install --only-binary=:all:\n",
    "a key with a space (a plain ': ' read as a mapping)": "a:\n  - run: x\n  - echo a: b\n",
    "two mapping values": "a: b: c\n",
    "tab indent": "a:\n\tb: c\n",
    "unterminated quote": "a: 'b\n",
    "text after a quote": "a: 'b' c\n",
    "bad block header": "a: |x\n  y\n",
    "duplicate key": "a: 1\nb: 2\na: 3\n",
    "duplicate key in an item": "s:\n  - a: 1\n    a: 2\n",
    "alias": "a: *x\n",
    "continued plain scalar": "a: b\n  c\n",
    "unclosed flow sequence": "a: [b, c\n",
    "flow mapping": "a: {b: c}\n",
    "plain starting with '- '": "a: - b\n",
}


def self_test():
    problems = []
    try:
        parse(GOOD, "GOOD")
    except YamlError as e:
        problems.append("the reader rejects a valid document: %s" % e)
    for label, doc in BAD.items():
        try:
            parse(doc, label)
            problems.append("the reader accepts an invalid document: %s" % label)
        except YamlError:
            pass
    # Two items with the same key are fine; the key set restarts per item.
    try:
        parse("s:\n  - a: 1\n  - a: 2\n", "items")
    except YamlError as e:
        problems.append("the reader rejects one key in two items: %s" % e)
    return problems


# ---- The workflows ---------------------------------------------------------------------------

USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
PIN_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
TAG_COMMENT_RE = re.compile(r"^\s+#\s*v\d+\.\d+\.\d+\s*$")


def env_values(text, key):
    return re.findall(r"^\s+%s:\s*(\S+)\s*$" % re.escape(key), text, re.M)


def main(argv):
    if len(argv) != 2:
        print("usage: check_workflows.py <.github/workflows>")
        return 2
    wdir = argv[1]
    problems = self_test()

    present = sorted(f for f in os.listdir(wdir) if f.endswith((".yml", ".yaml")))
    if present != sorted(EXPECTED_FILES):
        problems.append("workflow files are %r, expected exactly %r" % (present, EXPECTED_FILES))

    texts = {}
    for f in EXPECTED_FILES:
        path = os.path.join(wdir, f)
        if not os.path.isfile(path):
            problems.append("%s is missing" % f)
            continue
        with open(path, "rb") as fh:
            text = fh.read().decode("utf-8")
        texts[f] = text
        try:
            parse(text, f)
        except YamlError as e:
            problems.append("YAML: %s" % e)
        uses = 0
        for n, line in enumerate(text.split("\n"), 1):
            m = USES_RE.match(line)
            if not m:
                continue
            uses += 1
            if not PIN_RE.match(m.group(1)):
                problems.append("%s:%d: not pinned to a commit: %s" % (f, n, m.group(1)))
            if not TAG_COMMENT_RE.match(m.group(2)):
                problems.append("%s:%d: a pinned action needs a '# vX.Y.Z' comment" % (f, n))
        if uses == 0:
            problems.append("%s: no `uses:` found -- the pin check would be vacuous" % f)

    if len(texts) == len(EXPECTED_FILES):
        for key in ("SDK_REPO", "SDK_REF"):
            vals = {f: env_values(t, key) for f, t in texts.items()}
            flat = [v for vs in vals.values() for v in vs]
            if any(len(vs) != 1 for vs in vals.values()) or len(set(flat)) != 1:
                problems.append("%s must be set exactly once per workflow, to one value: %r" % (key, vals))
        for v in env_values(texts["release.yml"], "SDK_REF"):
            if not re.match(r"^[0-9a-f]{40}$", v):
                problems.append("SDK_REF is not a 40-hex commit: %s" % v)

        rel = texts["release.yml"]
        job = rel.find("\n  release:")
        guard = rel.find("[0-9a-f]{40}", job)
        first_checkout = rel.find("uses: actions/checkout@", job)
        if job < 0 or guard < 0 or first_checkout < 0 or guard > first_checkout:
            problems.append("release.yml: the SDK_REF guard must run before any checkout in the release job")
        if rel.count("secrets.") != 1 or rel.count("secrets.GHOST_DEV_KEY_PEM") != 1:
            problems.append("release.yml: the signing secret must be named exactly once, and no other secret")
        if texts["ci.yml"].count("secrets.") != 0:
            problems.append("ci.yml must not use any secret")
        if not re.search(r"pip install [^\n]*--require-hashes[^\n]*--only-binary=:all:", rel):
            problems.append("release.yml: pip must install with --require-hashes --only-binary=:all:")
        if 'trap \'rm -f "$key"\' EXIT' not in rel or "$RUNNER_TEMP/dev-private.pem" not in rel:
            problems.append("release.yml: the key goes to $RUNNER_TEMP and a trap removes it")

    for p in problems:
        print("FAIL: " + p)
    if problems:
        print("%d problem(s)" % len(problems))
        return 1
    print("workflows: %d file(s) parsed, reader self-test passed (%d rejections)" % (len(texts), len(BAD)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
