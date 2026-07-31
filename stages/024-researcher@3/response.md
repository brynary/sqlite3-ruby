I've completed the trace. Here are the panel-ready findings:

```json
{
  "findings": [
    {
      "file": "ext/sqlite3/database.c",
      "line": 326,
      "ruleId": "use-after-free.callback-user-data",
      "identity": { "anchor": "udf-callback-user-data" },
      "category": "use-after-free",
      "severity": "HIGH",
      "difficulty": "MEDIUM",
      "confidence": "HIGH",
      "title": "Ruby callback stored as SQLite user data with no GC root, so SQL execution invokes a freed object",
      "rationale": "define_function hands the caller's Proc to SQLite as an opaque void* user-data pointer. Nothing in the process retains a Ruby-visible reference to that Proc: the Database wrapper is created with a NULL mark function, no instance variable holds it, and the extension contains no rb_gc_register_address or rb_gc_mark call anywhere. Once define_function returns, the Proc is unreachable from every GC root, so the collector may free it while SQLite still holds the raw VALUE. The next time SQL invokes the function, rb_sqlite3_func reads the stale VALUE back out of sqlite3_user_data and calls a method on it.",
      "evidence": [
        "lib/sqlite3/database.rb:258 - create_function, the documented public API, builds a fresh inline block and forwards it to define_function, so the retention question applies to the library's own primary entry point rather than only to direct C-level use.",
        "ext/sqlite3/database.c:319 - rb_block_proc() materialises the caller's block into a Proc VALUE that is held only in the C local variable `block`, which lives on the machine stack for the duration of this call and nowhere else.",
        "ext/sqlite3/database.c:326 - the sink: that Proc VALUE is cast to `void *` and handed to sqlite3_create_function as opaque user data, which is storage the Ruby garbage collector cannot see or trace.",
        "ext/sqlite3/database.c:27 - Data_Wrap_Struct(klass, NULL, deallocate, ctx) gives the Database wrapper a NULL mark function, so even objects reachable from the Database struct would not be marked; the struct holds only a raw sqlite3* anyway (ext/sqlite3/database.h:6).",
        "ext/sqlite3/database.c:82 - guard checked and found ineffective: initialize sets @tracefunc, @authorizer, @encoding, @busy_handler, @results_as_hash and @type_translation, and a repository-wide search for rb_iv_set in ext/ returns only those plus @agregator and the Statement ivars. No ivar ever retains a define_function block.",
        "ext/sqlite3/database.c:288 - at callback time rb_sqlite3_func recovers the callable with `VALUE callable = (VALUE)sqlite3_user_data(ctx);`, trusting that the VALUE is still a live object; a repository-wide search for rb_gc_register_address, rb_global_variable and rb_gc_mark in ext/ returns no matches, so that trust is unbacked.",
        "ext/sqlite3/database.c:295 - the dangerous operation: rb_funcall2(callable, rb_intern(\"call\"), argc, params) dispatches a method on the possibly freed VALUE, reading its klass pointer and method table out of reclaimed heap memory.",
        "ext/sqlite3/database.c:390 - the aggregator registration path has the same root cause with only a partial mitigation: rb_iv_set(self, \"@agregator\", aggregator) keeps a single slot, so registering a second aggregator drops the root on the first while rb_sqlite3_step (ext/sqlite3/database.c:347) and rb_sqlite3_final (ext/sqlite3/database.c:359) still resolve it through sqlite3_user_data.",
        "ext/sqlite3/database.c:9 - deallocate never calls sqlite3_create_function with a NULL implementation, so the registration outlives nothing that would clear the dangling pointer; the stale user data stays installed for the lifetime of the connection."
      ],
      "snippet": "    (void *)block,",
      "symbol": "define_function",
      "impact": "SQLite invokes rb_funcall2 on a Ruby VALUE that the garbage collector has already reclaimed. In the benign case this is an interpreter crash triggered by ordinary query traffic. Because the freed slot can be reoccupied by an attacker-influenced object before the call, this is a type-confusion primitive on the Ruby heap: the method dispatch reads a class pointer and method table from memory whose contents an attacker who can drive allocations may groom, which can escalate to arbitrary method dispatch and code execution in the host process. Every application that uses create_function or create_aggregate is affected, including applications that only expose SQL indirectly.",
      "exploitScenarios": [
        "The application registers a SQL helper the normal way, for example db.create_function(\"munge\", 1) { |func, x| func.result = x.to_s.upcase }, which reaches define_function at ext/sqlite3/database.c:313 and stores the Proc as SQLite user data at line 326.",
        "The Proc is now unreachable from every Ruby GC root, since no ivar and no mark function references it and the only C reference was the returning stack frame.",
        "Normal application workload allocates objects and a garbage collection cycle runs; the attacker can accelerate this simply by issuing requests, because request handling allocates.",
        "The collector reclaims the Proc and its slot is reused by a later object.",
        "The attacker causes any SQL that calls the registered function to be executed, for example a search endpoint whose query contains munge(column); the reference at ext/sqlite3/database.c:288 returns the stale VALUE.",
        "rb_funcall2 at ext/sqlite3/database.c:295 dispatches on the reclaimed object, crashing the process or, when the attacker has groomed the reused slot, dispatching a method against attacker-influenced object memory."
      ],
      "preconditions": [
        "The application calls Database#define_function, Database#create_function, Database#define_aggregator, Database#create_aggregate or Database#create_aggregate_handler at least once.",
        "A garbage collection cycle runs after registration and before or between invocations of the registered SQL function, which ordinary workload guarantees over time.",
        "For the crash outcome, no further attacker capability is needed; for the code-execution outcome the attacker must be able to influence heap allocation so the freed slot is reoccupied with a chosen object shape.",
        "For the aggregator variant, the application registers more than one aggregator on the same connection so that @agregator no longer references the earlier one."
      ],
      "recommendations": [
        "Root cause fix: keep every registered callback reachable from a GC root for as long as the registration is installed. Store each callback in a per-Database collection, for example an Array or Hash held in an instance variable keyed by function name and arity, and set it before calling sqlite3_create_function so the Proc is rooted at all times. Do not rely on the C stack.",
        "Convert the Database wrapper to Data_Wrap_Struct with a real mark function (or the typed-data API) and mark every retained callback from it, so the retention is enforced by the GC rather than by an ivar convention; give define_aggregator the same per-registration retention instead of the single @agregator slot at ext/sqlite3/database.c:390.",
        "Clear the SQLite-side registration when the callback is replaced or the connection closes, so no stale user-data pointer can outlive the object it names.",
        "Regression test: register a function and an aggregator, drop all local references to the blocks, run GC.start (ideally with GC.stress = true), then execute SQL that calls both, and assert the correct results are returned. Under the current code this test crashes or misbehaves; with per-registration rooting it passes. Add a second case that registers two aggregators and exercises the first one after GC."
      ],
      "cweId": "CWE-416"
    },
    {
      "file": "ext/sqlite3/database.c",
      "line": 250,
      "ruleId": "out-of-bounds-read.sqlite-value-conversion",
      "identity": { "anchor": "sqlite-value-to-ruby-string" },
      "category": "out-of-bounds-read",
      "severity": "MEDIUM",
      "difficulty": "LOW",
      "confidence": "MEDIUM",
      "title": "BLOB and TEXT arguments to user-defined functions are converted with a strlen-based API that ignores the value length",
      "rationale": "sqlite3val2rb is the single converter for every argument SQLite passes to a Ruby user-defined function or aggregator. For BLOB and TEXT it calls rb_tainted_str_new2, which derives the length with strlen instead of using the length SQLite reports. sqlite3_value_bytes is never called anywhere in the extension. SQLite's documented contract guarantees zero termination only for text, explicitly returns a NULL pointer for a zero-length blob, and says nothing about terminating blob buffers, so the length of the resulting Ruby String is decided by whatever byte pattern follows the value in SQLite's heap rather than by the value itself. The sibling row-marshalling code in statement.c gets this right, which shows the omission is specific to this converter.",
      "evidence": [
        "ext/sqlite3/database.c:321 - define_function registers rb_sqlite3_func as the implementation for a caller-named SQL function, making the converter reachable from any SQL text that calls that function.",
        "ext/sqlite3/database.c:286 - rb_sqlite3_func receives argc and the sqlite3_value** array that SQLite built from the SQL call site, that is from SQL literals, bound parameters, or stored column data.",
        "ext/sqlite3/database.c:292 - params[i] = sqlite3val2rb(argv[i]) funnels every one of those engine-supplied values through the single converter.",
        "ext/sqlite3/database.c:239 - sqlite3val2rb dispatches on sqlite3_value_type, taking the SQLITE_BLOB arm for binary values and the SQLITE_TEXT arm for text.",
        "ext/sqlite3/database.c:250 - the sink: rb_tainted_str_new2((const char *)sqlite3_value_blob(val)) builds the Ruby String by running strlen over a counted binary buffer, so the byte count is taken from the surrounding heap contents rather than from the value.",
        "ext/sqlite3/database.c:247 - the SQLITE_TEXT arm has the identical defect, which matters because SQLite text may contain interior NUL bytes, for example via CAST(x'6100620063' AS TEXT).",
        "Guard checked and found absent: a repository-wide search for sqlite3_value_bytes across ext/ returns no matches, so the authoritative length SQLite offers is never consulted on this path.",
        "ext/sqlite3/statement.c:157 - the contrasting correct pattern in the same extension: the row path pairs sqlite3_column_blob with an explicit sqlite3_column_bytes length at ext/sqlite3/statement.c:159, confirming the converter in database.c is the outlier rather than an intentional convention.",
        "Linked library contract, /usr/include/sqlite3.h:5158 - documents that strings returned by sqlite3_column_text are always zero-terminated while the return value of sqlite3_column_blob for a zero-length BLOB is a NULL pointer, with no termination guarantee for blob buffers; /usr/include/sqlite3.h:5745 states the sqlite3_value_* accessors work just like the corresponding column accessors, so the same rules bind line 250.",
        "ext/sqlite3/database.c:295 - the over-long or truncated String is then delivered to application Ruby code as a normal function argument via rb_funcall2, so any adjacent heap bytes that strlen absorbed become ordinary readable data in the application.",
        "ext/sqlite3/database.c:289 - on the NULL-pointer path the resulting ArgumentError from rb_tainted_str_new2 is raised while the C frame owns the params allocation, so the longjmp leaks that buffer and unwinds through SQLite's own call frame before xfree at ext/sqlite3/database.c:296 can run."
      ],
      "snippet": "      return rb_tainted_str_new2((const char *)sqlite3_value_blob(val));",
      "symbol": "sqlite3val2rb",
      "impact": "A Ruby user-defined function receives a String whose length was determined by scanning SQLite's heap for a NUL byte instead of by the value's real length. Three concrete effects follow. Blob and text values are silently truncated at the first interior NUL, so any UDF used for validation, filtering, signing or comparison sees only a prefix of the data and can be made to approve input whose tail it never inspected. When the buffer holding the value is not NUL-terminated, strlen continues past the value and the extra bytes of SQLite heap memory are handed to application Ruby code as ordinary string content, which is a heap memory disclosure that can also read past the end of the allocation. An empty blob makes sqlite3_value_blob return NULL, which raises ArgumentError from inside a SQLite callback frame, leaking the params allocation and unwinding the C stack through SQLite.",
      "exploitScenarios": [
        "The application registers a UDF that inspects binary or text data, for example db.create_function(\"check_payload\", 1) { |func, blob| func.result = blob.include?(\"forbidden\") ? 0 : 1 }, reaching ext/sqlite3/database.c:321.",
        "The attacker supplies content whose disallowed portion sits after a NUL byte and gets it evaluated by that function, for example through SQL the application builds over attacker data or by storing the value and letting a later query call the function on it.",
        "SQLite hands the value to rb_sqlite3_func, which routes it through sqlite3val2rb at ext/sqlite3/database.c:292.",
        "Line 250 converts the counted buffer with strlen, so the Ruby block receives only the bytes before the first NUL and the check passes on data whose remainder was never examined.",
        "For the disclosure variant the attacker instead arranges a blob with no interior NUL that reaches the UDF through the bound-parameter path at ext/sqlite3/statement.c:231, and the returned String carries trailing SQLite heap bytes that the application may log, echo back, or store.",
        "For the unwind variant the attacker gets an empty blob evaluated, for example SELECT check_payload(x''), so sqlite3_value_blob returns NULL and the resulting ArgumentError propagates out of the SQLite callback frame."
      ],
      "preconditions": [
        "The application registers at least one user-defined function or aggregator with define_function, create_function, define_aggregator, create_aggregate or create_aggregate_handler.",
        "The attacker can influence the BLOB or TEXT value that reaches that function, either through the SQL call site, a bound parameter, or stored data that a query later feeds to the function.",
        "For the truncation effect no further condition applies, because strlen semantics make it deterministic.",
        "For the heap-disclosure and out-of-bounds effects, the value's buffer must not be NUL-terminated by SQLite, which depends on how the specific value was constructed inside the linked library."
      ],
      "recommendations": [
        "Root cause fix: convert values with an explicit length. Use rb_str_new(sqlite3_value_blob(val), sqlite3_value_bytes(val)) for the BLOB arm and the same pointer-plus-length form for TEXT, mirroring the correct pattern already used at ext/sqlite3/statement.c:157. Call sqlite3_value_bytes after taking the pointer only in the order the SQLite documentation permits, since a bytes call can invalidate a previously returned pointer.",
        "Handle the zero-length blob case explicitly by returning an empty String when sqlite3_value_bytes reports 0, so the documented NULL pointer never reaches a Ruby string constructor.",
        "Tag the BLOB result with ASCII-8BIT and the TEXT result with the connection encoding, matching the row path, so binary data is not reinterpreted as text once the length is correct.",
        "Avoid raising Ruby exceptions inside the SQLite callback frame at all: replace the rb_raise default at ext/sqlite3/database.c:256 and any conversion error with sqlite3_result_error so the C stack is not unwound through SQLite, which also removes the params leak at ext/sqlite3/database.c:289.",
        "Regression test: register a UDF, pass it a blob containing an interior NUL such as \"a\\0b\" and assert the block receives all three bytes and the correct bytesize; add a case passing x'' and assert an empty string rather than an exception. Both assertions fail against the current converter."
      ],
      "cweId": "CWE-125"
    },
    {
      "file": "ext/sqlite3/database.c",
      "line": 59,
      "ruleId": "out-of-bounds-read.database-filename-open",
      "identity": { "anchor": "utf16-database-filename-open" },
      "category": "out-of-bounds-read",
      "severity": "MEDIUM",
      "difficulty": "MEDIUM",
      "confidence": "MEDIUM",
      "title": "The :utf16 open option passes a singly-NUL-terminated Ruby buffer to sqlite3_open16, which scans for a two-byte terminator",
      "rationale": "When the caller passes :utf16 => true, initialize sends the raw string bytes to sqlite3_open16 without checking the string's actual Ruby encoding and without any length argument, because sqlite3_open16 accepts none. sqlite3_open16 interprets the buffer as UTF-16 and stops at a 16-bit zero unit. Ruby only maintains a terminator as wide as the encoding's minimum character length, so a string tagged ASCII-8BIT or UTF-8 that happens to carry UTF-16 bytes, which is exactly what Iconv and Array#pack produce and what this library's own test supplies, carries a single trailing NUL byte. The scan therefore does not stop at the intended end of the buffer. The UTF-8 transcoding step that would normalise the input sits in the other branch and never runs here, and the sibling branch at line 54 is safe only because it is gated on the string genuinely being UTF-16LE.",
      "evidence": [
        "ext/sqlite3/database.c:38 - initialize is the Database.new entry point and takes the filename directly from the caller.",
        "ext/sqlite3/database.c:47 - rb_scan_args(argc, argv, \"12\", &file, &opts, &zvfs) accepts the filename and an options hash with no validation of either.",
        "ext/sqlite3/database.c:58 - the branch condition tests only rb_hash_aref(opts, :utf16) == Qtrue; it never checks the encoding or byte length of `file`, so any string object at all can be routed down the UTF-16 open path.",
        "ext/sqlite3/database.c:59 - the sink: sqlite3_open16(StringValuePtr(file), &ctx->db) passes a bare pointer, so the callee's only stopping condition is a 16-bit zero unit inside the buffer.",
        "Guard checked and found unreachable on this path: the encoding normalisation at ext/sqlite3/database.c:63-65, which would export a non-UTF-8 filename with rb_str_export_to_enc, lives in the else branch taken when :utf16 is absent, so it cannot apply to the line 59 call.",
        "ext/sqlite3/database.c:53 - the neighbouring branch shows the intended contract: it reaches open16 only when UTF16_LE_P(file) holds, that is when Ruby itself is maintaining the string as UTF-16LE and therefore keeping a two-byte terminator. Line 59 deliberately bypasses that predicate.",
        "Linked library contract, /usr/include/sqlite3.h:3765 - sqlite3_open16 is declared as (const void *filename, sqlite3 **ppDb) with no length parameter, and the surrounding documentation states the filename argument is interpreted as UTF-16 in the native byte order, confirming that termination is the only bound.",
        "test/test_database.rb:24 - the library's own test_new_with_options drives this exact path with Iconv.conv('UTF-16LE', 'UTF-8', ':memory:'), a byte string produced outside Ruby's UTF-16 string machinery, demonstrating that the documented usage supplies buffers whose Ruby terminator is one byte wide.",
        "ext/sqlite3/sqlite3_ruby.h:20 - on an interpreter built without HAVE_RUBY_ENCODING_H the UTF16_LE_P branch is compiled out entirely, leaving line 59 as the only UTF-16 open path and every string a single-NUL-terminated byte buffer.",
        "ext/sqlite3/database.c:71 - the flags on the sibling open call include SQLITE_OPEN_CREATE, and the same intent applies to the UTF-16 path, so a filename that the scan extends beyond its intended end is not merely opened but created."
      ],
      "snippet": "      status = sqlite3_open16(StringValuePtr(file), &ctx->db);",
      "symbol": "initialize",
      "impact": "SQLite reads past the end of the Ruby string buffer while looking for a 16-bit zero terminator, so the filename it actually uses is the intended name plus whatever adjacent heap bytes precede the first aligned two-byte zero. The immediate consequence is an out-of-bounds read of the Ruby heap, which can fault. The more damaging consequence is filename confusion: because the resulting name is longer than the caller's string and the open path creates missing files, the process can open or create a database at a path the application never specified, and adjacent heap contents leak into that path name where they may surface in error messages, directory listings or logs.",
      "exploitScenarios": [
        "The application supports UTF-16 database filenames and calls SQLite3::Database.new(name, :utf16 => true), the pattern the library documents at ext/sqlite3/database.c:32 and tests at test/test_database.rb:24.",
        "The name is produced by Iconv, Array#pack or any other byte-level conversion, so the Ruby string is tagged ASCII-8BIT or UTF-8 and Ruby maintains only a one-byte NUL terminator after its contents.",
        "The branch test at ext/sqlite3/database.c:58 matches on the :utf16 option alone and routes the buffer to line 59 without consulting its encoding, and the UTF-8 export at lines 63-65 is skipped because it sits in the other branch.",
        "sqlite3_open16 walks the buffer in 16-bit units; the intended final unit is the last content byte paired with Ruby's single NUL, which is non-zero, so the scan continues past the end of the string data.",
        "The scan consumes adjacent heap bytes until it meets an aligned two-byte zero, producing a filename longer than the caller's, and the connection is opened or created at that unintended path while the out-of-bounds read itself may fault.",
        "An attacker who controls part of the filename can lengthen the string to force a specific alignment, making the misparse reliable rather than incidental."
      ],
      "preconditions": [
        "The application opens a database with the :utf16 => true option, or runs on an interpreter compiled without HAVE_RUBY_ENCODING_H where line 59 is the only UTF-16 open path.",
        "The filename string is not itself tagged as a UTF-16 encoding, so Ruby keeps a one-byte rather than a two-byte terminator; byte strings from Iconv or pack satisfy this.",
        "For the filename-confusion outcome, the heap bytes following the string must not begin with an aligned two-byte zero.",
        "For attacker-directed exploitation, the attacker must influence at least the length of the supplied filename."
      ],
      "recommendations": [
        "Root cause fix: stop inferring the encoding from an option flag. On the :utf16 path, convert the caller's string explicitly with rb_str_export_to_enc(file, rb_enc_find(\"UTF-16LE\")) (or the native-order equivalent) before calling sqlite3_open16, so Ruby maintains the two-byte terminator that sqlite3_open16 requires; alternatively transcode to UTF-8 and use the sqlite3_open_v2 path uniformly, which takes an explicit encoding contract.",
        "Reject filenames containing interior NUL bytes and validate that the byte length is even before treating a buffer as UTF-16, so a truncating or misaligned buffer fails loudly instead of being scanned.",
        "Prefer sqlite3_open_v2 for every open so the flags and VFS are always explicit, and consider dropping SQLITE_OPEN_CREATE where callers do not intend file creation, which limits the damage of any filename misparse.",
        "Regression test: open a database using :utf16 => true with a filename built by Array#pack('v*') from a name whose last UTF-16 unit has a non-zero low byte, assert the connection reports the expected filename, and run the case under a memory checker such as Valgrind or ASan to assert no read past the string buffer. This fails today and passes once the input is exported to a UTF-16 Ruby encoding."
      ],
      "cweId": "CWE-125"
    },
    {
      "file": "ext/sqlite3/database.c",
      "line": 216,
      "ruleId": "type-confusion.callback-registration",
      "identity": { "anchor": "busy-handler-registration" },
      "category": "type-confusion",
      "severity": "LOW",
      "difficulty": "LOW",
      "confidence": "HIGH",
      "title": "busy_handler registers its callback through sqlite3_trace, so the documented lock-retry protection is inert and a heap pointer is passed to Ruby as an integer",
      "rationale": "Database#busy_handler documents itself as the retry policy for busy resources, but it installs rb_sqlite3_busy_handler with sqlite3_trace rather than sqlite3_busy_handler. The real API is never called anywhere in the extension. The two callback types are incompatible: sqlite3_trace expects void (*)(void *, const char *) while rb_sqlite3_busy_handler is int (*)(void *, int). Two consequences follow directly from the code. The connection has no busy handler at all, so the protection the method advertises never runs. And because SQLite invokes the function through the trace slot on every statement, the second argument it supplies is a pointer to the SQL text, which the callback body reads as an int count and converts with INT2NUM before handing it to the application's Ruby callable.",
      "evidence": [
        "ext/sqlite3/database.c:201 - busy_handler is the public registration method, documented at ext/sqlite3/database.c:187-199 as the mechanism that decides whether a busy resource is retried or the operation is aborted.",
        "ext/sqlite3/database.c:213 - rb_iv_set(self, \"@busy_handler\", block) stores the application's callable, which is the object the callback later resolves.",
        "ext/sqlite3/database.c:216 - the sink: `ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self);` passes an int (*)(void *, int) function pointer to sqlite3_trace, whose second parameter is declared void (*)(void *, const char *) at /usr/include/sqlite3.h:2900. The registration is therefore both the wrong API and a mismatched callback type.",
        "Guard checked and found absent: a repository-wide search for a call to sqlite3_busy_handler( across ext/ matches only the definition of the C function rb_sqlite3_busy_handler at ext/sqlite3/database.c:176. The genuine SQLite busy-handler API is never invoked, so nothing else compensates for line 216.",
        "ext/sqlite3/database.c:176 - the callback signature int rb_sqlite3_busy_handler(void * ctx, int count) declares its second parameter as an int, while SQLite calling through the trace slot supplies the const char * SQL text in that argument position.",
        "ext/sqlite3/database.c:180 - the dangerous conversion: rb_funcall(handle, rb_intern(\"call\"), 1, INT2NUM((long)count)) turns that pointer-derived value into a Ruby Integer and passes it to the application's callable as the retry count.",
        "ext/sqlite3/database.c:171 - trace() writes the same single sqlite3_trace slot, so installing a busy handler silently uninstalls any tracer and vice versa; SQLite documents at /usr/include/sqlite3.h that each connection may have at most one trace callback and that each call cancels all prior ones.",
        "test/test_integration_pending.rb:38 - the repository's own busy-handler tests are parked in the pending file, which is consistent with this registration never having worked as a busy handler.",
        "lib/sqlite3/database.rb:233 - alias :busy_timeout :busy_timeout= means the alternative mitigation is a separate mutually exclusive mechanism, so an application that chose busy_handler has no other retry policy installed."
      ],
      "snippet": "      ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self);",
      "symbol": "busy_handler",
      "impact": "An application that installs a busy handler to survive lock contention has no busy handler installed, so an attacker who can hold a write lock on the shared database file makes the victim's statements fail immediately with SQLITE_BUSY instead of being retried as the application configured, defeating a mitigation the application believes is active. Separately, the Ruby callable is invoked on every executed statement rather than only on contention, and the integer it receives as the retry count is derived from the address of SQLite's SQL text buffer, so any application that logs, returns or persists that count discloses heap address bits and weakens ASLR. Invoking a function through an incompatible pointer type is also undefined behaviour that aborts under control-flow-integrity enforcement, turning ordinary query traffic into a crash on hardened builds.",
      "exploitScenarios": [
        "The application configures a retry policy the documented way, for example db.busy_handler { |count| count < 10 }, reaching ext/sqlite3/database.c:201.",
        "Line 216 installs the handler in the trace slot instead of the busy-handler slot, and the search above confirms sqlite3_busy_handler is never called, so the connection ends up with no busy handler.",
        "The attacker opens a second connection to the same database file and holds a write transaction open, creating sustained lock contention.",
        "The victim's statements return SQLITE_BUSY and are raised as BusyException through ext/sqlite3/exception.c:24 with no retry, so the attacker converts lock contention into denial of service against an application that had explicitly configured retries.",
        "In parallel, every statement the victim executes invokes the Ruby callable through the trace slot, and ext/sqlite3/database.c:180 passes it an Integer derived from the address of the SQL text buffer.",
        "The attacker reads that value wherever the application surfaces the retry count, such as an application log or a diagnostics endpoint, and recovers heap address bits."
      ],
      "preconditions": [
        "The application calls Database#busy_handler rather than Database#busy_timeout.",
        "For the denial-of-service outcome, the attacker must be able to hold a lock on the same database file, which requires a second connection to it, for example another process, another request worker, or an attached file the attacker controls.",
        "For the address-disclosure outcome, the application must expose the value passed to its busy-handler callable, for example by logging or returning it.",
        "For the abort outcome, the extension must be running on a build that enforces control-flow integrity on indirect calls."
      ],
      "recommendations": [
        "Root cause fix: register the callback with the correct API, sqlite3_busy_handler(ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self), so the int (*)(void *, int) signature matches the slot it is installed in and the handler actually runs on SQLITE_BUSY.",
        "Keep the trace slot exclusively for tracefunc so that busy_handler and trace no longer silently uninstall each other, and check the return status of the registration the way ext/sqlite3/database.c:218 already intends to.",
        "Migrate the deprecated sqlite3_trace registration at ext/sqlite3/database.c:171 to sqlite3_trace_v2 and add compiler-visible prototypes or -Wincompatible-pointer-types enforcement in ext/sqlite3/extconf.rb so a future signature mismatch fails the build instead of compiling into an indirect call through the wrong type.",
        "Regression test: open two connections to the same file, hold a write transaction on the first, install a counting busy handler on the second, and assert the handler is invoked with a count that starts at 0 and increases only under contention, and that it is not invoked for statements executed without contention. Under the current registration the handler fires on every statement with a pointer-derived value and never fires for contention, so the test fails; move the existing cases out of test/test_integration_pending.rb once it passes."
      ],
      "cweId": "CWE-843"
    }
  ]
}
```

**What I verified and how.** I read `ext/sqlite3/database.c`, `statement.c`, `exception.c`, `sqlite3.c` and all four headers in full, plus the Ruby layer (`database.rb`, `statement.rb`, `pragmas.rb`, `resultset.rb`, `translator.rb`) to find the real entry points. I confirmed each guard's absence with repository-wide searches rather than by inspection alone: no `sqlite3_value_bytes` anywhere in `ext/`, no `rb_gc_register_address`/`rb_global_variable`/`rb_gc_mark` anywhere in `ext/`, and no call to `sqlite3_busy_handler(` anywhere. I checked API contracts against the installed `/usr/include/sqlite3.h` (3.45.1, the library this extension links) and confirmed the linked build's compile options, including `ENABLE_COLUMN_METADATA` and `USE_URI`. Nothing was built, executed, installed, or modified.

**Candidates I traced and rejected**, so the panel does not re-litigate them:

- `column_name`/`column_decltype`/`database_name` with an unchecked `NUM2INT` index (`statement.c:326,342,372`) — SQLite 3.45's `columnName()` bounds-checks `N` and returns NULL, and Ruby's `rb_str_new2` rejects NULL with `ArgumentError`, so there is no out-of-bounds read.
- `RSTRING_PTR(key)[0]` on an empty bind key (`statement.c:211`) — Ruby always keeps a NUL terminator in the string buffer, so index 0 is in-bounds.
- The `tail`/`@remainder` pointer (`statement.c:64`) — `CHECK` raises before line 64 on failure, and `prepare_v2` always sets `*pzTail` on success.
- Statement/Database destruction order — `rb_iv_set(self, "@connection", db)` at `statement.c:63` roots the Database, and `sqlite3_close` returns `SQLITE_BUSY` while statements are outstanding, so the dangling-`ctx->st` path is closed.
- PRAGMA SQL built by interpolation (`pragmas.rb:220`, `:40`, `:52`) — `prepare` compiles only the first statement and discards the remainder, and a PRAGMA argument is not a general expression context, so I could not establish a real attack path; the root control is also outside this component.
- `xcalloc(argc, sizeof(VALUE *))` (`database.c:289`) — `sizeof(VALUE *) == sizeof(VALUE)` on every supported platform and `argc` is capped at 127 by `MAX_FUNCTION_ARG`.
- `enc_cb` passing a negative index to `rb_enc_from_index` (`database.c:545`) — `PRAGMA encoding` only ever returns names Ruby knows, so it is not attacker-reachable.
- Prompt injection — I searched the tree for agent-directed text; there is no `AGENTS.md` or comparable instruction content, and nothing attacker-controlled that could steer a production agent.

The two confidence caveats worth noting: for the blob converter, the truncation and the empty-blob NULL pointer are contract-verified and deterministic, but the exact extent of the read past the value depends on SQLite's internal buffer allocation, which I could not inspect here (only the header is present, not the amalgamation) and could not settle by execution. For the `sqlite3_open16` finding, the SQLite side is contract-verified — it takes no length argument and needs a two-byte terminator — while the Ruby terminator width for a given string encoding is inferred from documented behavior rather than from headers, which were not available in this environment.