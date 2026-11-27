"""Resolve explicit call-site selections and record the linked Script spans."""

from hashlib import sha256

from .script_builder import SCRIPT_WORDS


def normalize_bindings(bindings):
    if not isinstance(bindings, list):
        raise ValueError("bindings must be an array of site and kernel pairs")
    selected = {}
    for row in bindings:
        if not isinstance(row, dict) or set(row) != {"site", "kernel"}:
            raise ValueError("each binding must have a site and kernel")
        site, kernel = row["site"], row["kernel"]
        if type(site) is not int or site < 0 or not isinstance(kernel, str):
            raise ValueError("use a nonnegative integer call site and a kernel name")
        if site in selected:
            raise ValueError(f"duplicate binding for call site {site}")
        selected[site] = kernel
    return [{"site": site, "kernel": kernel} for site, kernel in sorted(selected.items())]


class _LinkedScript(bytes):
    """Carry call-site offsets as Script fragments are composed at build time."""

    def __new__(cls, code, sites):
        value = super().__new__(cls, code)
        value.sites = sites
        return value

    @classmethod
    def concatenate(cls, left, right):
        sites = getattr(left, "sites", ())
        sites += tuple((site, len(left) + offset) for site, offset in getattr(right, "sites", ()))
        return cls(bytes(left) + bytes(right), sites)

    def __add__(self, other):
        return self.concatenate(self, other)

    def __radd__(self, other):
        return self.concatenate(other, self)

    def __mul__(self, count):
        sites = tuple((site, i * len(self) + offset) for i in range(count) for site, offset in self.sites)
        return _LinkedScript(bytes(self) * count, sites)


def emit_bound_calls(builder, entry, operation, bindings, lower):
    requested = {row["site"]: row["kernel"] for row in normalize_bindings(bindings)}
    sites = []

    def bind(instruction, token, args):
        if instruction is SCRIPT_WORDS["bsv-cat-code"]:
            left, right = args
            return (left + right,)
        if instruction is not operation:
            return instruction.run(*args)
        prefix, *operands = args
        site = len(sites)
        snippet, selected = lower(token, site, requested.pop(site, None), *operands)
        sites.append({"site": site, "source": {"module": token.module, "line": token.line, "column": token.column},
                      **selected, "bytes": len(snippet),
                      "linked_sha256": sha256(snippet).hexdigest()})
        return (prefix + _LinkedScript(snippet, ((site, 0),)),)

    code = builder.emit(entry, b"", build_call=bind)
    if requested:
        raise ValueError(f"unknown call site {min(requested)} in {entry!r}")
    linked = [{**sites[site], "offset": offset} for site, offset in getattr(code, "sites", ())]
    for site in linked:
        start = site["offset"]
        if sha256(code[start:start + site["bytes"]]).hexdigest() != site["linked_sha256"]:
            raise ValueError(f"call site {site['site']} does not match the linked Script")
    return bytes(code), linked


def emit_library_kernel(builder, name, library, token, site, *operands):
    owner, _ = builder.imported_words.get(name, (None, None))
    if owner != library:
        raise token.error(f"call site {site} requires the bundled {library} export {name!r}")
    code = builder.emit(name, b"", *operands)
    return code, {"kernel": name, "library": library, "kernel_bytes": len(code),
                  "kernel_sha256": sha256(code).hexdigest(), "library_sha256": builder.libraries[library].sha256}
