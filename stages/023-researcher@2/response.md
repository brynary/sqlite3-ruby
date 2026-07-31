I've completed a full read of the C extension (`database.c`, `statement.c`, `exception.c`, `sqlite3.c`, all headers), the Ruby layer that drives it, and the SQLite API contracts in the installed `sqlite3.h`. Here is my assessment.

## Outcome

Four memory/FFI findings, all in `ext/sqlite3/database.c`, all on the SQLite→Ruby callback boundary. The headline issue is that **user-defined function callbacks are stored as raw `VALUE`s inside SQLite and are never GC-rooted**, producing a use-after-free on a live Ruby object.

**1. `define_function` block is never rooted → UAF (HIGH).** `define_function` reifies the caller's block with `rb_block_proc()` (`ext/sqlite3/database.c:319`) and hands the raw `VALUE` to SQLite as opaque user data at `ext/sqlite3/database.c:326`. It then returns without a single `rb_iv_set`, `rb_gc_register_address`, or global-root call, and the Database wrapper is built with a **NULL mark function** (`ext/sqlite3/database.c:27`). SQLite's `FuncDef.pUserData` lives in SQLite's own `malloc` arena, which Ruby's GC never scans, so once the C frame unwinds the Proc has no reachable root. Any later `SELECT myfunc(...)` reads the stale `VALUE` back via `sqlite3_user_data` (`:288`) and dispatches on it at `:295`. I confirmed by search that nothing on the Ruby side retains it either — `create_function` at `lib/sqlite3/database.rb:258` passes a fresh block and drops it.

**2. `define_aggregator` retains only one object (MEDIUM).** Same registration pattern at `:384`, but with a partial defense: `rb_iv_set(self, "@agregator", aggregator)` at `:390`. It is a single ivar slot, so registering a second aggregator overwrites the first one's only root while SQLite still holds its pointer. Distinct control, same rule and anchor, so I gave it an `identity.instance`.

**3. Busy handler installed through `sqlite3_trace` (MEDIUM).** `ext/sqlite3/database.c:216` passes `rb_sqlite3_busy_handler`, declared `int(*)(void*, int)` at `:176`, into `sqlite3_trace`, whose prototype at `sqlite3.h:3342` is `void(*)(void*, const char*)`. Calling through an incompatible function-pointer type is undefined behavior; on the common SysV x86-64 ABI it does not crash but silently reinterprets the `const char *zSql` argument as the `int count`, so `INT2NUM((long)count)` at `:180` hands the low 32 bits of a live heap pointer to the Ruby callback. It also means no busy handler is ever actually registered and any installed tracer is silently cancelled.

**4. BLOB values converted with `strlen` (MEDIUM).** `ext/sqlite3/database.c:250` does `rb_tainted_str_new2(sqlite3_value_blob(val))` — `sqlite3_value_bytes` is never called, so the string length comes from `strlen` rather than the blob's real length. The parallel code in `statement.c:157` does this correctly with an explicit length, which is good evidence the omission is unintentional. I rated confidence MEDIUM: the interior-NUL truncation and the NULL-pointer-for-zero-length-blob raise are certain from the code and the documented API, but confirming a read past the allocation end would require executing against a specific SQLite build, which I did not do.

I also checked and **did not** report: the `sizeof(VALUE *)` vs `sizeof(VALUE)` allocation at `:289`/`:348` (equal on every mainstream ABI, so no under-allocation), the unchecked `NUM2INT` column indices in `statement.c` (SQLite bounds-checks these internally and returns NULL), and the `(int)RSTRING_LEN` narrowing in `bind_param` (requires a >2GB Ruby string). No attacker-controlled agent-instruction files exist in the tree.

```json
{
  "findings": [
    {
      "file": "ext/sqlite3/database.c",
      "line": 326,
      "ruleId": "use-after-free.callback-registration",
      "identity": { "anchor": "udf-callback-retention", "instance": "scalar-function" },
      "category": "use-after-free",
      "severity": "HIGH",
      "difficulty": "MEDIUM",
      "confidence": "HIGH",
      "title": "Scalar UDF block stored in SQLite as an unrooted Ruby VALUE, causing use-after-free when the Proc is collected",
      "rationale": "define_function casts the block's Ruby VALUE to void* and stores it inside SQLite's FuncDef as opaque user data. SQLite's allocations are not part of the Ruby object graph and are not scanned by the GC, and the function leaves behind no ivar, global root, or mark function that would keep the Proc alive. Once the registering C frame unwinds the Proc is unreachable, so any GC cycle may free and recycle its slot. The next SQL invocation of the function reads that stale VALUE back out of SQLite and performs a method dispatch on it.",
      "evidence": [
        "lib/sqlite3/database.rb:258 - Database#create_function, the documented public API, builds a fresh wrapper block and passes it straight to define_function, keeping no Ruby-side reference to it.",
        "ext/sqlite3/database.c:319 - `VALUE block = rb_block_proc();` reifies the caller's block into a new Proc object whose only reference is this C local variable.",
        "ext/sqlite3/database.c:326 - the Proc VALUE is cast to `void *` and passed as the pUserData argument of sqlite3_create_function, moving it into SQLite's malloc arena where Ruby's GC never scans.",
        "ext/sqlite3/database.c:313-334 - the whole body of define_function contains no rb_iv_set, no rb_gc_register_address, and no global root registration for `block`; I checked every line and this retention guard is simply absent, so the last GC-visible reference dies when the frame returns.",
        "ext/sqlite3/database.c:27 - the Database object is created with `Data_Wrap_Struct(klass, NULL, deallocate, ctx)`; the mark-function slot is NULL, so the wrapper cannot mark the Proc either. A repository-wide search for rb_gc_mark, rb_gc_register_address, and RB_GC_GUARD across ext/ returns no matches, confirming no alternative root exists.",
        "ext/sqlite3/database.c:288 - at invocation time rb_sqlite3_func recovers the stored pointer with `VALUE callable = (VALUE)sqlite3_user_data(ctx);`, which is now a dangling reference to a freed or recycled RVALUE slot.",
        "ext/sqlite3/database.c:295 - `rb_funcall2(callable, rb_intern(\"call\"), argc, params)` performs a real method dispatch on that freed VALUE, reading its class pointer and method table from memory that may already belong to a different object."
      ],
      "snippet": "    (void *)block,",
      "symbol": "define_function",
      "impact": "A Ruby object slot is used after it has been freed. Because Ruby reuses RVALUE slots for new objects of arbitrary classes, the freed Proc slot can be reoccupied by an attacker-influenced object, turning the dispatch at database.c:295 into a type confusion: the interpreter reads a class pointer and method table from memory whose contents the attacker helped shape. That yields memory corruption and a realistic path to arbitrary code execution in the host process, and at minimum a reliable interpreter crash amounting to denial of service on any application that registers a custom SQL function.",
      "exploitScenarios": [
        "The application registers a custom SQL function once at startup, for example `db.create_function('munge', 1) { |func, x| ... }`, which reaches define_function and stores the wrapper Proc into SQLite as unrooted user data.",
        "The registering C frame returns, so the Proc's only remaining reference is SQLite's pUserData pointer, invisible to Ruby's GC.",
        "The attacker drives ordinary application traffic that allocates Ruby objects until a major GC runs; no special privilege is needed because any request handler creates garbage, and the attacker can also inflate pressure with large query result sets.",
        "The GC finds no reference to the Proc, sweeps it, and returns its slot to the free list.",
        "The attacker grooms the heap so that the recycled slot is refilled by an object whose contents they influence, such as a long String or an Array built from their own request data.",
        "The attacker triggers any SQL statement that calls the registered function, for example a search endpoint that emits `SELECT munge(col) FROM t`.",
        "rb_sqlite3_func reads the stale VALUE at database.c:288 and calls rb_funcall2 on it at database.c:295, dispatching against the attacker-shaped object and producing type confusion and memory corruption."
      ],
      "preconditions": [
        "The application registers at least one scalar SQL function through Database#define_function or Database#create_function.",
        "A garbage collection cycle occurs between registration and invocation, which is the normal steady state for any long-running process.",
        "The attacker can cause the registered function to be invoked by some SQL statement the application executes, or can wait for the application to invoke it on its own.",
        "For the escalation from crash to controlled type confusion, the attacker needs enough influence over allocation patterns to occupy the recycled object slot."
      ],
      "recommendations": [
        "Root the callback for the lifetime of the registration: keep every registered Proc in a Ruby-visible container owned by the Database object, for example an array or hash stored in an ivar keyed by function name, so the GC can reach it, and register a mark function for the Database wrapper instead of passing NULL to Data_Wrap_Struct at database.c:27.",
        "Alternatively, allocate a small C struct as the pUserData, register it with the GC through a properly marked wrapper object, and pass the xDestroy destructor argument of sqlite3_create_function_v2 so the root is released when SQLite drops the function.",
        "Harden the callback entry point by validating the recovered VALUE before dispatch and by wrapping the rb_funcall2 at database.c:295 in rb_protect so a bad state raises cleanly instead of corrupting memory.",
        "Add a regression test that defines a function, drops all Ruby references to the block, calls GC.start several times with GC.stress enabled, and then executes SQL invoking the function; under the current code this crashes or misbehaves, and after the fix it must return the correct value."
      ],
      "cweId": "CWE-416"
    },
    {
      "file": "ext/sqlite3/database.c",
      "line": 384,
      "ruleId": "use-after-free.callback-registration",
      "identity": { "anchor": "udf-callback-retention", "instance": "aggregator" },
      "category": "use-after-free",
      "severity": "MEDIUM",
      "difficulty": "MEDIUM",
      "confidence": "HIGH",
      "title": "Aggregator object retained in a single overwritable ivar, so registering a second aggregator unroots the first while SQLite still holds its pointer",
      "rationale": "define_aggregator stores the aggregator object's raw VALUE into SQLite as user data and attempts to keep it alive with a single instance variable. The retention slot is not keyed by function name, so each new registration overwrites the previous root. SQLite continues to hold pointers to every aggregator ever registered, so all but the most recent become unreachable by the GC while still being dereferenced by the step and final callbacks.",
      "evidence": [
        "lib/sqlite3/database.rb:338 - Database#create_aggregate builds a proxy object and passes it to define_aggregator; lib/sqlite3/database.rb:403 does the same for create_aggregate_handler, so applications commonly register several aggregators on one connection.",
        "ext/sqlite3/database.c:384 - `(void *)aggregator,` casts the aggregator object's VALUE and passes it as the pUserData argument of sqlite3_create_function, placing it in SQLite memory that the Ruby GC does not scan.",
        "ext/sqlite3/database.c:390 - `rb_iv_set(self, \"@agregator\", aggregator);` is the only retention guard, and it is ineffective because it is a single fixed ivar name rather than a per-function collection; the second call to define_aggregator replaces the first object with the second and drops the first root entirely.",
        "ext/sqlite3/database.c:27 - the Database wrapper passes NULL as the mark function to Data_Wrap_Struct, so the wrapper provides no fallback marking for aggregator objects.",
        "ext/sqlite3/database.c:347 - rb_sqlite3_step recovers the pointer with `VALUE callable = (VALUE)sqlite3_user_data(ctx);`, which for any but the last-registered aggregator is now unrooted.",
        "ext/sqlite3/database.c:353 - `rb_funcall2(callable, rb_intern(\"step\"), argc, params)` dispatches on that stale VALUE for every row the aggregate processes.",
        "ext/sqlite3/database.c:360 - rb_sqlite3_final performs the same dereference by calling `finalize` on the recovered VALUE at the end of the aggregate."
      ],
      "snippet": "    (void *)aggregator,",
      "symbol": "define_aggregator",
      "impact": "Any aggregate function other than the most recently registered one can have its backing Ruby object collected while SQLite still holds a pointer to it. Invoking that aggregate then dispatches `step` and `finalize` against a freed or recycled object slot, causing memory corruption or an interpreter crash. Because the aggregate's step callback runs once per row, an attacker who controls the row count gets many dispatches against the stale slot, improving the odds of turning the corruption into controlled type confusion.",
      "exploitScenarios": [
        "The application registers two or more aggregate functions on the same Database connection, for example a `total_length` aggregate followed by a `median` aggregate.",
        "The second call to define_aggregator overwrites the @agregator ivar at database.c:390, leaving the first aggregator object with no GC-visible reference while SQLite's FuncDef still points at it.",
        "The attacker generates ordinary allocation churn until a GC cycle sweeps the first aggregator object and frees its slot.",
        "The attacker arranges for a new object of their choosing to reoccupy the freed slot.",
        "The attacker triggers a query that uses the first aggregate function over a table they can grow, so rb_sqlite3_step dispatches `step` against the recycled slot once per row and rb_sqlite3_final then dispatches `finalize`, producing type confusion and memory corruption."
      ],
      "preconditions": [
        "The application registers more than one aggregate function on the same Database object, which is the non-default but entirely ordinary case.",
        "A garbage collection cycle occurs after the overwriting registration and before the older aggregate is used.",
        "The attacker can cause a query that invokes the older aggregate function to run."
      ],
      "recommendations": [
        "Replace the single @agregator ivar at database.c:390 with a per-connection collection keyed by function name, such as a Hash ivar, so every registered aggregator keeps a distinct GC-visible root for as long as SQLite holds its pointer.",
        "Combine this with the fix for the scalar case by introducing one shared, GC-marked registry for all user-defined function callbacks and giving the Database wrapper a real mark function instead of the NULL passed at database.c:27.",
        "Use sqlite3_create_function_v2 with an xDestroy callback so the Ruby-side root is released exactly when SQLite discards the function definition, preventing the opposite leak.",
        "Add a regression test that registers two different aggregators, forces GC.start under GC.stress, then invokes the first aggregate over a multi-row table and asserts the correct aggregate value is returned."
      ],
      "cweId": "CWE-416"
    },
    {
      "file": "ext/sqlite3/database.c",
      "line": 216,
      "ruleId": "unsafe-ffi.callback-signature",
      "identity": { "anchor": "busy-handler-registration" },
      "category": "unsafe-ffi",
      "severity": "MEDIUM",
      "difficulty": "MEDIUM",
      "confidence": "HIGH",
      "title": "Busy handler registered through sqlite3_trace with an incompatible function pointer type, leaking a heap pointer into the Ruby callback",
      "rationale": "Database#busy_handler installs its C callback using sqlite3_trace rather than sqlite3_busy_handler. The callback's declared type does not match the type sqlite3_trace expects, so SQLite invokes it through an incompatible function pointer. On the common x86-64 SysV ABI the call does not fault; instead the const char* SQL text pointer that SQLite passes as the second trace argument is reinterpreted as the int count parameter, and the truncated pointer value is converted into a Ruby Integer and handed to the application's handler. The registration also silently cancels any previously installed tracer and never establishes a real busy handler.",
      "evidence": [
        "lib/sqlite3/database.rb:233 - the Ruby layer exposes busy_timeout and the C busy_handler method as the documented concurrency-retry API, so applications reach this registration through ordinary supported use.",
        "ext/sqlite3/database.c:176 - `static int rb_sqlite3_busy_handler(void * ctx, int count)` declares the callback with the busy-handler signature int(*)(void*, int), taking an integer retry count as its second parameter.",
        "ext/sqlite3/database.c:215-216 - that function is passed as the xTrace argument of sqlite3_trace: `ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self);`. This is the dangerous operation, an indirect call set up through a mismatched function pointer type.",
        "/usr/include/sqlite3.h:3342-3343 - the installed SQLite header declares `sqlite3_trace(sqlite3*, void(*xTrace)(void*,const char*), void*)`, confirming the second callback parameter SQLite will supply is a const char* SQL string pointer, not an int.",
        "/usr/include/sqlite3.h:2861 - the correct API `sqlite3_busy_handler(sqlite3*,int(*)(void*,int),void*)` exists and matches the callback's actual signature, proving the wrong function was called rather than the signature being deliberate.",
        "ext/sqlite3/database.c:180 - inside the callback, `INT2NUM((long)count)` converts whatever landed in the second parameter into a Ruby Integer; because SQLite actually passed a pointer there, this converts the low bits of a live heap address into a Ruby object.",
        "ext/sqlite3/database.c:180 - `rb_funcall(handle, rb_intern(\"call\"), 1, INT2NUM((long)count))` then delivers that pointer-derived Integer to the application-supplied handler as if it were a legitimate retry count.",
        "ext/sqlite3/database.c:171 - trace() registers the real tracer through the same sqlite3_trace slot, and sqlite3.h:3415-3416 states each sqlite3_trace call overrides all prior ones, so calling busy_handler silently uninstalls any tracer the application had installed. This is the guard that does not exist: nothing detects or reports the conflict."
      ],
      "snippet": "      ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self);",
      "symbol": "busy_handler",
      "impact": "Every statement execution hands the Ruby busy-handler block the low 32 bits of a live SQLite heap pointer disguised as a retry count. Any application that logs, echoes, or otherwise surfaces that value discloses heap layout information and defeats ASLR for the process, giving an attacker the address primitive that turns the separate use-after-free issues on this same callback boundary into a reliably exploitable condition. Independently, calling through a mismatched function pointer type is undefined behavior that aborts immediately on builds hardened with Control Flow Integrity, and the intended busy-retry protection is never actually installed, so applications relying on it silently lose their SQLITE_BUSY handling and their tracer.",
      "exploitScenarios": [
        "The application calls db.busy_handler { |count| ... } to add concurrency retry logic, believing it registered a busy handler.",
        "database.c:216 instead installs rb_sqlite3_busy_handler in SQLite's trace slot, where SQLite will call it as void(*)(void*, const char*).",
        "The attacker issues any request that causes the application to execute a SQL statement, which makes SQLite invoke the trace callback and pass the expanded SQL text pointer in the second argument register.",
        "rb_sqlite3_busy_handler reads that register as its int count parameter and converts the truncated heap address into a Ruby Integer at database.c:180.",
        "The Ruby handler receives the pointer-derived value; where the application records it into a log, a metric, or an error message, the attacker reads back a live heap address and defeats ASLR.",
        "The attacker combines the leaked address with the unrooted-callback use-after-free on the same boundary to place a controlled object at a predictable location.",
        "Separately, on a CFI-hardened build the very first statement execution aborts the process at the indirect call, giving an unauthenticated attacker a denial of service."
      ],
      "preconditions": [
        "The application calls Database#busy_handler to register a handler, which is the documented way to add retry behaviour.",
        "For the address disclosure to reach the attacker, the application must surface the count value it receives, for example by logging it or including it in an error response.",
        "For the abort variant, the extension must be built against a toolchain that enforces Control Flow Integrity on indirect calls."
      ],
      "recommendations": [
        "Change database.c:215-216 to call sqlite3_busy_handler(ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self), which matches the callback's declared int(*)(void*, int) signature and actually installs the retry behaviour the API promises.",
        "Stop suppressing the compiler diagnostic for this class of error: the incompatible-pointer warning already identifies it, so build the extension with -Werror=incompatible-pointer-types so a signature mismatch on any SQLite callback fails the build.",
        "Audit the other callback registrations on this boundary, in particular sqlite3_trace at database.c:171 and sqlite3_set_authorizer at database.c:508, to confirm each callback's declared type matches the API it is passed to.",
        "Add a regression test that opens two connections, holds a write lock on one, registers a busy handler on the other, and asserts the handler is invoked with small monotonically increasing integers starting near zero rather than large pointer-derived values, and a second test asserting that installing a busy handler does not cancel a previously installed tracer."
      ],
      "cweId": "CWE-686"
    },
    {
      "file": "ext/sqlite3/database.c",
      "line": 250,
      "ruleId": "out-of-bounds-read.value-conversion",
      "identity": { "anchor": "sqlite-value-to-ruby-blob" },
      "category": "out-of-bounds-read",
      "severity": "MEDIUM",
      "difficulty": "MEDIUM",
      "confidence": "MEDIUM",
      "title": "BLOB arguments to user-defined functions are converted with strlen instead of sqlite3_value_bytes",
      "rationale": "sqlite3val2rb builds the Ruby String for a BLOB argument with rb_tainted_str_new2, which is the NUL-terminated constructor and derives the length by calling strlen on the pointer. The blob's actual length, available from sqlite3_value_bytes, is never consulted. Binary blob data has no NUL-termination contract, so the length used to build the Ruby String is unrelated to the length of the underlying buffer. The equivalent code in the statement result path does pass an explicit length, showing this is an omission rather than a deliberate choice.",
      "evidence": [
        "ext/sqlite3/statement.c:53 - sqlite3_prepare_v2 is the ingress for application SQL, so an attacker who influences a query, or who controls the rows a query reads, controls which values are passed to a user-defined function.",
        "ext/sqlite3/database.c:286 - when that SQL invokes a registered function, SQLite calls rb_sqlite3_func with an sqlite3_value** array holding the argument values, which may originate from blob columns in the database file or from x'..' literals in the SQL text.",
        "ext/sqlite3/database.c:292 - `params[i] = sqlite3val2rb(argv[i]);` converts each engine-supplied value into a Ruby object with no length or nullity checks applied by the caller.",
        "ext/sqlite3/database.c:239 - sqlite3val2rb switches on sqlite3_value_type, so an argument whose stored type is BLOB reaches the SQLITE_BLOB branch.",
        "ext/sqlite3/database.c:250 - the sink: `return rb_tainted_str_new2((const char *)sqlite3_value_blob(val));` uses the NUL-terminated string constructor, so the String's length is whatever strlen finds, and sqlite3_value_bytes is never called anywhere in this file.",
        "ext/sqlite3/statement.c:157-160 - the parallel BLOB conversion on the statement result path correctly uses rb_tainted_str_new with an explicit sqlite3_column_bytes length argument, confirming the length-carrying idiom was known to the authors and simply not applied at database.c:250.",
        "/usr/include/sqlite3.h:5158-5159 - the documented contract states that only sqlite3_column_text results are always zero-terminated and that the blob accessor returns a NULL pointer for a zero-length BLOB; there is no zero-termination guarantee for blob data, and no NULL check guards database.c:250."
      ],
      "snippet": "      return rb_tainted_str_new2((const char *)sqlite3_value_blob(val));",
      "symbol": "sqlite3val2rb",
      "impact": "Blob arguments delivered to user-defined functions are silently wrong in a memory-unsafe way. A blob containing an interior NUL byte is truncated at that byte, so a function used for validation, signature checking, or comparison sees only the prefix an attacker chose to place before the NUL and can be made to approve data it never inspected. A zero-length blob makes sqlite3_value_blob return NULL, so rb_str_new2 raises ArgumentError from inside SQLite's VDBE frame, and because no rb_protect wraps any callback in this extension the resulting longjmp unwinds through SQLite's C stack, abandoning its cleanup and leaking the params allocation at database.c:289. Where the underlying blob buffer carries no trailing NUL, strlen walks past the end of the allocation and the excess heap bytes are copied into a Ruby String that the function returns to the application, disclosing adjacent heap memory.",
      "exploitScenarios": [
        "The application registers a user-defined function that receives column data, for example a validation or transformation helper created with db.create_function.",
        "The attacker stores a blob value they control into a table the application queries, for example by supplying a binary upload that is inserted with SQLite3::Blob, or influences a query that contains an x'..' blob literal.",
        "The application runs SQL that passes that blob to the registered function, so rb_sqlite3_func calls sqlite3val2rb on the attacker's value.",
        "For the truncation variant, the attacker prefixes the blob with an acceptable-looking value followed by a NUL byte and hides the rejected payload after it; database.c:250 truncates at the NUL so the Ruby function inspects and approves only the benign prefix while the full blob remains stored.",
        "For the exception variant, the attacker supplies a zero-length blob so sqlite3_value_blob returns NULL, rb_str_new2 raises, and the raise longjmps out of the SQLite callback frame, abandoning VDBE cleanup and leaking the params buffer allocated at database.c:289; repeating this exhausts memory.",
        "For the over-read variant, the attacker supplies a blob whose buffer is not NUL-terminated so strlen runs past the allocation, and reads the trailing heap bytes back out of whatever the application does with the function's result."
      ],
      "preconditions": [
        "The application registers at least one user-defined function or aggregate that receives a BLOB argument.",
        "The attacker can influence the blob content that reaches that function, either by storing rows or by influencing SQL text.",
        "For the over-read specifically, the blob's backing buffer must lack a trailing NUL byte; whether a given SQLite build guarantees one for every blob representation could only be settled by executing against that build, which I did not do, so this specific consequence is asserted with lower confidence than the truncation and NULL-pointer consequences, which follow directly from the documented API contract."
      ],
      "recommendations": [
        "Replace database.c:250 with a length-carrying conversion that mirrors the correct statement path, reading the length first and then the pointer, for example capturing `int len = sqlite3_value_bytes(val);` and building the String with rb_tainted_str_new(sqlite3_value_blob(val), len), handling len == 0 by returning an empty String rather than dereferencing a NULL pointer.",
        "Apply the same treatment to the adjacent SQLITE_TEXT branch at database.c:247 so text values carry their true byte length and embedded NULs are preserved consistently with statement.c:145.",
        "Wrap the Ruby invocations in every SQLite callback, including rb_funcall2 at database.c:295 and database.c:353, in rb_protect so a Ruby exception is converted into a SQLite error result instead of longjmping through SQLite's C frames and leaking the params allocation.",
        "Add a regression test that registers a function, passes it SQLite3::Blob values containing an interior NUL byte and a zero-length blob, and asserts the block receives a String of exactly the original bytesize with the NUL preserved and an empty String respectively."
      ],
      "cweId": "CWE-125"
    }
  ]
}
```