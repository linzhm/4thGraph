# 4thGraph Syntax Reference · v0.2.7

[简体中文](syntax.md)

This reference defines 4thGraph source tokens, declaration grammar, and compatibility syntax. Standard words follow Forth 2012 Core semantics within the supported subset. The language specification covers stack types, integer ranges, and transaction layouts. [Language semantics (Chinese)](specification.md) · [Forth 2012 Core](https://forth-standard.org/standard/core)

## 1. Tokens

- Source files use UTF-8. The compiler normalizes `CRLF` and `CR` to `LF`. Whitespace separates tokens, and newlines ordinarily have the same effect as spaces. `;`, `--`, `:`, `IF`, `ELSE`, and `THEN` are separate tokens. `work:` and `relation:` are each a single token.
- A standalone `(` starts a comment that ends at the next `)`, even across lines. A standalone `\` starts a comment that ends at the end of the line. Comments can appear between tokens.
- Keyword and word lookup use Unicode case folding. Standard spellings generally use lowercase, and native Script opcodes use `OP_*` spelling. Diagnostics can show the original spelling and its line and column.
- A `symbol` matches `[a-z][a-z0-9_-]*` after case folding. Symbols name locks, named inputs, byte parameters, stages, roles, values, ranges, and the words referenced by `relation:`. Ordinary definition names and the computation words referenced by `work:`, `gate:`, and `join:` are single tokens and can have spellings such as `+`.
- `REQUIRE` reads a filename from the same line and uses its original spelling. 4thGraph first resolves relative paths from the current source file's directory, then looks in the bundled standard library. When compiling source in memory without a source path, it starts from the working directory. `BSV` is a case-insensitive built-in module alias.
- The `bsv-` prefix is reserved. Extension interfaces specify where their words execute. For example, `bsv-sign` runs on the host.

## 2. Canonical grammar

The grammar uses EBNF. Quotation marks denote literal tokens, `[ … ]` denotes an optional element, and `{ … }` denotes zero or more repetitions. `nonspace` is any non-whitespace character. Numbers and filenames are each a single token. The filename after `REQUIRE` must be on the same line.

```ebnf
source           = { item } ;
item             = requirement | definition | declaration ;
requirement      = "require", filename ;
filename         = nonspace, { nonspace } ;
alphanumeric     = ascii-letter | digit ;
symbol           = ascii-letter, { alphanumeric | "_" | "-" } ;

definition       = ":", word-name, stack-effect, { instruction }, ";" ;
stack-effect     = "(", { stack-type }, "--", { stack-type }, ")" ;
instruction      = straight-instruction | branch ;
straight-instruction = call | cell-literal | byte-literal | range-check ;
call             = word-name ;
byte-literal     = "bytes-hex", hex-pairs ;
range-check      = "check-range", symbol ;
branch           = "if", { instruction }, [ "else", { instruction } ], "then" ;

declaration      = bytes-param | lock | range | work | join | gate | split-authority | recovery
                 | independent | workflow-input | stage | relation ;
bytes-param      = "bytes-param:", symbol, integer, ";" ;
lock             = "lock:", symbol, "(", { named-input }, ")",
                   { instruction }, ";" ;
named-input      = symbol, ":", stack-type ;
range            = "range:", symbol, numeric-type, integer, integer, ";" ;
work             = "work:", symbol, symbol, word-name, symbol, ";" ;
join             = "join:", symbol, symbol, symbol, word-name, ";" ;
gate             = "gate:", symbol, symbol, word-name, symbol, ";" ;
split-authority  = "split-authority:", symbol, ";" ;
recovery         = "recovery:", block-height, symbol, ";" ;
independent      = "independent-submit:", symbol, ";" ;
workflow-input   = "workflow-input:", symbol, "u32", ";" ;
stage            = "stage:", symbol, symbol, symbol, symbol, symbol, ";" ;
relation         = "relation:", symbol, symbol, ";" ;

stack-type       = built-in-type | declared-range | backend-type ;
built-in-type    = numeric-type | "bytes" | "script" | "transaction"
                 | "utxo" | "outpoint" | "request" ;
numeric-type     = "cell" | "u32" | "route" | "script-int" ;
integer          = decimal | "#", decimal
                 | "$", signed-hex | "%", signed-binary ;
decimal          = [ "-" ], digit, { digit } ;
signed-hex       = [ "-" ], hex-digit, { hex-digit } ;
signed-binary    = [ "-" ], binary-digit, { binary-digit } ;
hex-pairs        = hex-digit, hex-digit, { hex-digit, hex-digit } ;
cell-literal     = integer | quoted-character ;
```

`ascii-letter` is `a` through `z`, `digit` is `0` through `9`, `binary-digit` is `0` or `1`, and `hex-digit` is `0` through `9`, `a` through `f`, or `A` through `F`. `decimal`, `signed-hex`, `signed-binary`, and `hex-pairs` each form a single token. A minus sign follows a base prefix, as in `$-ff`. `block-height` is a decimal number of one to nine digits in the range 1 through 499,999,999.

A quoted character is one printable character between single quotes, as in `'A'` or `' '`. Numeric and character literals produce a `cell`. Numeric literals accept integers in `[-2^63, 2^64)` and normalize them to signed 64-bit cells. The compiler reads range bounds and byte parameter lengths as mathematical integers.

A `word-name` is a single token. Control words, source declarations, and the `bsv-` prefix are reserved in definitions. A `call` resolves to a named input, built-in word, import, or earlier definition in scope. Write each `named-input` as one token, such as `signature:bytes`. Include whitespace after the opening parenthesis. The empty input list is `( )`.

## 3. Declarations and parsing

| Declaration | Argument order and constraints |
| --- | --- |
| `REQUIRE` | Load the file named on the same line at this point in the source |
| `( input-types -- output-types )` | Follows the definition name. Each side lists types from bottom to top and may be empty |
| `bytes-param:` | Parameter name and unsigned 32-bit byte length. Supply the value at compile time with `--bind-bytes NAME=HEX` |
| `lock:` | Lock name, named witness inputs in push order, and a verification body. The body leaves one `cell` or ends with `verify` consuming the last `cell` |
| `range:` | Range name, numeric base type, inclusive lower bound, and exclusive upper bound. The interval must be nonempty and fit the base type |
| `work:` | Step, input value, computation word, and signer role. The word must have effect `u32 -- u32` |
| `join:` | Step, left work step, right work step, and routing word. The word must have effect `u32 u32 -- route` |
| `gate:` | Step, input value, guard word, and signer role. The word must have effect `u32 -- cell`. A nonzero result permits execution to continue |
| `split-authority:` | Signer role for the split transaction |
| `recovery:` | Absolute block height and refund signer role. The lock commits to that height. The earliest confirming block is one block later |
| `independent-submit:` | A gate, work step, or linear state stage that requires a separate transaction boundary |
| `workflow-input:` | Initial value name and the type `u32` |
| `stage:` | Stage name, computation word, input value name, output value name, and signer role. Values form directed dependencies |
| `relation:` | Transition word and routing word, with effects `u32 -- u32` and `u32 -- route`, respectively |

- Top-level directives and declarations take effect as the compiler reads the source. Definition bodies call computation, conversion, construction, and verification words.
- A stack-effect comment containing `--` follows the name in a colon definition. Standard Forth treats it as a comment. 4thGraph uses it as a static type contract. The signature can use the types known at that point, and the body can call definitions and imports already in scope or built-in words. `IF` consumes a `cell`. Both branches must leave the same ordered stack types at the join.
- The compiler resolves the computation words in `work:`, `gate:`, and `join:` as it reads them. It resolves the work steps named by `join:`, the computation words and value dependencies of `stage:`, and both words in `relation:` when building the corresponding plan. Stage declaration order can differ from dependency order.
- A parallel plan needs two distinct work steps, a join, and a split signer role. A gate is optional. A linear plan needs an initial value, one or more `u32 -- u32` stages, and a final `u32 -- route` stage. Each linear value has one producer and at most one consumer. Two-stage plans support `fused`, `serial`, and `atomic`. Longer chains use `serial`. The step names `deploy`, `split`, and `fused` are reserved. Both plan styles can include a recovery rule and independent submission constraints. [Transaction graph (Chinese)](specification.md#交易图)
- `relation:` requires `REQUIRE stdlib/verify.fth`. A source file can declare one relation independently of workflow declarations. The relation identifies the state transition to verify. The compiler selects an implementation based on available backends, policy, and budget. [Build and replay a relation](stdlib.md#verification-paths)

4thGraph statically checks the inputs and outputs described by stack-effect comments. Declarations such as `range:`, `work:`, and `relation:` control numeric checks, transaction scheduling, and verification relations. They follow the Forth practice of defining words with their own arguments and terminators. Full Forth systems provide `CREATE` and `DOES>` for implementing defining words. [Forth 2012 CREATE](https://forth-standard.org/standard/core/CREATE) · [Forth 2012 DOES>](https://forth-standard.org/standard/core/DOES)

TypeScript reads type annotations from JSDoc, and Rust uses explicit attributes to influence compilation. 4thGraph places type contracts with word definitions and expresses constraints on transactions and verification through source declarations. [TypeScript JSDoc](https://www.typescriptlang.org/docs/handbook/jsdoc-supported-types.html) · [Rust attributes](https://doc.rust-lang.org/reference/attributes.html)

### 3.1 Named inputs and locking checks

- `bytes-param: name size ;` declares a fixed-length build parameter. Pass each value with `--bind-bytes NAME=HEX`. Repeat the option to bind multiple parameters. The compiler checks each binding and byte length as it reads the declaration. A missing, duplicate, undeclared, or incorrectly sized binding fails the build. Using the parameter name in the body reads the bound byte constant.
- `lock:` declares a standalone spending entry for compilation and validation. Define reusable checks as ordinary words and use `verify` in their bodies to abort on failure.
- `lock:` and CLI `--entry` check canonical ScriptNum encoding and the declared numeric range before the body runs. Use `--assume-input-ranges` for a fragment whose caller has already performed those checks.
- `lock:` lists witness inputs from left to right in push order, which is the stack's bottom-to-top order. Input names are local to the body. They must be unique and distinct from words already in scope. The body runs in Forth postfix order. Script uses the sole remaining `cell` for the final decision. Nonzero passes and zero fails. A terminal `verify` can take that cell and lower directly to Script's final truth check. An earlier `verify` consumes its operand and aborts when it is zero.
- The body and the words it calls must compile to Script. `IF … [ELSE …] THEN` consumes one `cell` as its condition, and both branches must leave the same ordered stack types. The compiler schedules the values needed in each branch and preserves the order of checks. [Forth 2012 IF](https://forth-standard.org/standard/core/IF)

In a stack effect, the left side of `--` lists the items a word reads and the right side lists what it leaves on the main stack. Both sides list items from bottom to top. Use `dup` explicitly to preserve a value that a later word needs. The table uses `x`, `y`, and `flag` to show the positions of values. Stack effects in definitions use type names such as `bytes` and `cell`.

| Operation | Main stack effect | Meaning |
| --- | --- | --- |
| `dup` | `x -- x x` | Copies the top item |
| `drop` | `x --` | Discards the top item |
| `verify`, `OP_VERIFY` | `flag --` | Consumes the result and aborts immediately if it is zero |
| `OP_EQUALVERIFY` | `x y --` | Consumes two byte strings and aborts if they differ |
| `OP_CHECKSIG` | `signature public-key -- flag` | Consumes the signature and public key and leaves the verification result |
| `OP_CHECKSIGVERIFY` | `signature public-key --` | Consumes the signature and public key and aborts if signature verification fails |

In Script construction words, `op-toaltstack` and `op-fromaltstack` emit `OP_TOALTSTACK` and `OP_FROMALTSTACK` respectively. At Script runtime, these instructions move a value from the main stack to the alt stack or back.

Use `over` and `2dup` to copy existing stack items and `swap`, `rot`, and `nip` to rearrange the main stack. Gforth workflows can use `DO … LOOP` for host iteration. Script construction words can use `bsv-repeat-code` to expand a fixed number of copies of an instruction fragment. [Forth 2012 Core](https://forth-standard.org/standard/core) · [Forth 2012 DO](https://forth-standard.org/standard/core/DO)

Operations use postfix notation (RPN). `2 3 +` pushes both values, then `+` consumes them and leaves `5`. `+`, `-`, and `*` use wrapping 64-bit `cell` arithmetic. `=`, `<`, and `>` produce Forth flags. Use `u32+` for unsigned 32-bit addition and `int+`, `int-`, and `int*` for ScriptNum arithmetic. For byte strings, `bytes-cat` concatenates and `bytes=` compares. `OP_SIZE` preserves the input and leaves its length. `OP_SPLIT` consumes the input and offset and leaves two pieces. [Language semantics (Chinese)](specification.md)

When equality of two witness values is the sole spending condition, pass the `OP_EQUAL` result to a terminal `verify`. If the values differ, the result is `0` and the spend fails. This lock compiles to a single `OP_EQUAL` instruction.

```forth
REQUIRE BSV
lock: values-match ( left:bytes right:bytes )
    left right OP_EQUAL verify ;
```

### 3.2 Native Script opcodes

Use `REQUIRE BSV` at the top of a Script source to load `verify` and the supported subset of native `OP_*` words common to Genesis and Chronicle. These words use the compiler's static type checking. `OP_CAT` has stack effect `bytes bytes -- bytes`, and `OP_ADD` has stack effect `script-int script-int -- script-int`. When `OP_EQUAL` or `OP_CHECKSIG` returns normally, it produces `1` or `0`. The standard Forth comparison `=` produces `-1` or `0`. `OP_EQUALVERIFY` aborts if the byte strings differ, and `OP_CHECKSIG` checks the signature against the spending transaction. The `bsv.native_opcodes` field in `4thgraph --capabilities` lists the supported opcodes.

## 4. Public exports

`REQUIRE` resolves a file in the caller's dictionary and loads it once per build. A subsequent definition of the same name applies to later calls. Earlier definitions keep the words they resolved when compiled. The standard library catalog records public interfaces and backend requirements. Build diagnostics cover relative dependencies, cyclic imports, stack signature errors, and unsupported backends.

When a project file's relative path matches a standard library catalog name, build reports prefix the project path with `./`. The bundled library and the project file then have separate digests under names such as `std/bsv` and `./std/bsv`.

| Spelling | Contract |
| --- | --- |
| Type and operation | The type identifies the operand domain. `u32+` wraps at 32 bits, and `bytes-cat` concatenates byte strings |
| `source>target` | Explicit conversion. The interface describes truncation, extension, encoding, and out-of-range behavior |
| `…?` | Returns a Forth flag, `-1` for true or `0` for false. `u32<` and `bytes=` use their own comparison spellings |
| `…-lock` | A constructor that returns serialized locking Script. Its stack signature defines its parameters and results. A `lock:` declaration can define a spending check directly |
| `…-verify` | Aborts execution on failure. The signature specifies the results on success. The word name identifies the algorithm and any parameters that affect interoperability |

The `bsv.source_syntax` field in `4thgraph --capabilities` describes the canonical declarations and compatibility forms. Each record at `libraries.<module>.interfaces.<word>` has these fields.

| Field | Meaning |
| --- | --- |
| `name`, `module`, `aliases` | Canonical name, owning module, and resolvable compatibility names |
| `takes`, `gives` | Types ordered from bottom to top. The compiler checks these against the actual word definition on import |
| `build_parameters`, `runtime_inputs`, `transaction_context` | Parameter lists with a `name`, `type`, and `description` on each entry. An empty list indicates that the interface has no requirements in that field. Runtime inputs can include witness data unpacked by the backend |
| `failure_mode`, `failure` | `total` means the operation is defined throughout its declared domain. `abort` means a failed check ends execution. `failure` describes the conditions |
| `backends` | The compilation or execution backends that support the interface |

`groth16-bls12-381-verify` fixes its verification key at build time. The spending input supplies the proof and dynamic public signals. It returns a `groth16-verified` success marker. Applications can express additional constraints on the current outpoint, outputs, or authorization in the relation or transaction layer.

The `libraries` field in a build records the loaded files and the `sha256` of each file's original bytes. Registered standard libraries also have an `interface_sha256` computed from their module description. The compiler removes the digest field, sorts JSON keys, and uses compact serialization before hashing. A Groth16 build also records `verification_key_sha256`, the digest of the original verification key bytes.

## 5. Compatibility syntax

Use the canonical forms from section 2 for new source. The compiler also accepts these older forms.

| Compatibility form | Canonical form |
| --- | --- |
| Separate `bsv-effect: name inputs -- outputs ;` | `: name ( inputs -- outputs ) … ;` |
| Omitted final `;` after `work:`, `join:`, `gate:`, `split-authority:`, or `recovery:` | A separate closing `;` for each declaration |
| `independent-submit step`, or `step independent-submit` after defining a gate or work step | `independent-submit: step ;` |
| `verify: transition route ;` | `relation: transition route ;`, with `REQUIRE stdlib/verify.fth` |
| `groth16-verify` | `groth16-bls12-381-verify` |

Fixed-arity compatibility declarations end after the documented number of arguments. The implicit terminator applies to the five colon declarations listed in the table. The older prefix form of `independent-submit` also accepts a semicolon. `independent-submit:` and both relation spellings require one. The Groth16 alias uses the same verification semantics, and build output records the canonical name.

## 6. Minimal relation program

```forth
REQUIRE BSV
REQUIRE stdlib/u32.fth
REQUIRE stdlib/verify.fth

: decide ( u32 -- route ) 20 cell>u32 u32< if route-review else route-settle then ;

relation: u32-inc decide ;
```

`4thgraph-circuit` emits Circom. `4thgraph-verify` builds the transaction binding and the backend selection report. [Full commands](stdlib.md#verification-paths)

## 7. P2PKH locking check

When creating a transaction output, bind `owner-hash`, decode the compiled `script_hex` into bytes, and write those bytes into the output's `scriptPubKey`. To check an existing output, compare its `scriptPubKey` byte for byte with the result of compiling with the same parameter.

When spending, the node executes the `scriptPubKey` from the previous output referenced by the input. The witness supplies `signature` followed by `public-key`. `check-owner` compares `HASH160(public-key)` with the `owner-hash` embedded in the lock. The following `verify` aborts immediately on a mismatch. If it matches, `check-signature` uses `OP_CHECKSIG` and the same public key to verify the signature for the current spend and passes the result to the terminal `verify`. Both checks must pass to satisfy the lock. [Example source](../../src/fourthgraph/stdlib/native-p2pkh.fth)

```forth
REQUIRE BSV
bytes-param: owner-hash 20 ;

: check-owner ( bytes -- cell )
    OP_HASH160 owner-hash OP_EQUAL ;

: check-signature ( bytes bytes -- cell )
    OP_CHECKSIG ;

lock: p2pkh ( signature:bytes public-key:bytes )
    signature public-key dup
    check-owner verify
    check-signature verify ;
```

Run this command from the repository root with the public test vector's key hash.

```sh
4thgraph projects/p2pk-p2pkh-baseline/forth/p2pkh.fth --entry p2pkh \
  --bind-bytes owner-hash=751e76e8199196d454941c45d1b3a323f1433bd6
```

`dup` explicitly copies the public key at the top of the stack. `check-owner` consumes the copy, and the first `verify` consumes the comparison result. `check-signature` consumes the remaining signature and public key and leaves the value used for the final decision. The compiler combines the earlier `OP_EQUAL OP_VERIFY` into `OP_EQUALVERIFY` and lets Script read the final signature result directly. The build reports `25` in `script_bytes` for the sequence `OP_DUP OP_HASH160 <20-byte owner-hash> OP_EQUALVERIFY OP_CHECKSIG`.
