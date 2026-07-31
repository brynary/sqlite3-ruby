{
  "findings": [
    {
      "title": "Blob and text SQL values converted to Ruby strings without length, causing heap over-read into custom function callbacks",
      "category": "info-disclosure",
      "file": "ext/sqlite3/database.c",
      "line": 250,
      "ruleId": "info-disclosure.value-conversion",
      "identity": {
        "anchor": "sqlite-value-to-ruby-string"
      },
      "symbol": "sqlite3val2rb",
      "snippet": "      return rb_tainted_str_new2((const char *)sqlite3_value_blob(val));",
      "severity": "MEDIUM",
      "difficulty": "LOW",
      "confidence": "MEDIUM",
      "rationale": "The conversion routine that turns SQLite values into Ruby strings for every custom SQL function and aggregate argument uses the NUL-terminated-C-string constructor family with no length argument. SQLite BLOBs are documented as neither NUL-terminated nor NUL-free, so the implied strlen walks past the end of SQLite's blob buffer and copies adjacent process heap into a Ruby String handed to application code. The identical sibling path at ext/sqlite3/statement.c:157 does this correctly with an explicit sqlite3_column_bytes length, proving the length-aware pattern was available and that this is an omission rather than an intended contract. A repository-wide search confirms sqlite3_value_bytes is never called in this file, so no length or NULL guard exists anywhere on the path.",
      "impact": "A BLOB argument passed to any application-registered SQL function or aggregate is converted to a Ruby String using a NUL-terminated-C-string constructor with no length. Because SQLite BLOBs are neither NUL-terminated nor NUL-free, the implied strlen() walks off the end of SQLite's blob buffer and copies adjacent process heap memory into a Ruby String that is handed straight to application code. In a database process that heap holds other rows, cached database pages, prior SQL statement text and any credentials or PII inlined in it, so the caller receives an over-read of memory belonging to other data and other users. The same root control also truncates any legitimate blob at its first embedded NUL byte (silent data corruption of binary values), and for a zero-length blob sqlite3_value_blob returns a NULL pointer, so the conversion dereferences NULL and crashes the interpreter, giving an unauthenticated denial of service to whoever can store an empty blob.",
      "evidence": [
        "lib/sqlite3/database.rb:258 - Database#create_function is the public, in-scope Ruby entry point where an application registers a block as an SQL function; it forwards to define_function, so any application using custom SQL functions opts into the path below.",
        "ext/sqlite3/database.c:313 - define_function calls sqlite3_create_function and installs rb_sqlite3_func as the C trampoline SQLite will invoke during query evaluation; this is where the in-scope Ruby API crosses into the native extension, the scope boundary this data flow crosses.",
        "ext/sqlite3/database.c:286 - rb_sqlite3_func is entered by SQLite while evaluating a query, receiving sqlite3_value **argv that holds the argument values the SQL expression supplied, i.e. attacker-influenced row data or literals.",
        "ext/sqlite3/database.c:292 - the loop converts every argument with params[i] = sqlite3val2rb(argv[i]), so each untrusted SQL value reaches the conversion routine unfiltered.",
        "ext/sqlite3/database.c:239 - sqlite3_value_type(val) dispatches on the value's runtime type, selecting the SQLITE_BLOB branch whenever the argument is a blob column or a blob literal such as x'41', which the attacker chooses by controlling the stored data.",
        "ext/sqlite3/database.c:250 - SINK: rb_tainted_str_new2((const char *)sqlite3_value_blob(val)) builds the Ruby String from a bare pointer. The _new2 family takes a NUL-terminated C string and derives its length with strlen, so the copy continues past the blob's real end into adjacent heap until it happens to find a zero byte.",
        "Guard check (ineffective/absent): a search of ext/sqlite3/database.c returns zero occurrences of sqlite3_value_bytes, so no length is ever consulted on this path, and there is no NULL check on the returned pointer before it is treated as a string.",
        "ext/sqlite3/statement.c:157 - the sibling row-materialization path does the same conversion correctly, using rb_tainted_str_new with an explicit sqlite3_column_bytes(stmt, i) length at ext/sqlite3/statement.c:159. This proves the length-aware pattern was available and shows database.c:250 is a genuine omission rather than an intentional contract.",
        "/usr/include/sqlite3.h:5159 - the SQLite API contract states that the return value from sqlite3_column_blob() for a zero-length BLOB is a NULL pointer, and /usr/include/sqlite3.h:5694 states the sqlite3_value_* routines work just like the corresponding column access functions, confirming both the missing termination guarantee and the NULL-for-empty-blob case.",
        "ext/sqlite3/database.c:295 - rb_funcall2(callable, 'call', argc, params) passes the over-read String into the application's Ruby block, completing the flow from SQLite's heap to attacker-observable application data.",
        "ext/sqlite3/database.c:351 - the aggregate trampoline rb_sqlite3_step reaches the identical sqlite3val2rb conversion, so Database#create_aggregate and Database#create_aggregate_handler (lib/sqlite3/database.rb:303 and lib/sqlite3/database.rb:387) are a second reachable entry point for the same root control.",
        "ext/sqlite3/database.c:247 - the adjacent SQLITE_TEXT branch uses the same length-less constructor; sqlite3_value_text is documented as always zero-terminated so it does not over-read, but TEXT values containing an embedded NUL are still silently truncated by the same root defect."
      ],
      "exploitScenarios": [
        "Identify a target application that registers a custom SQL function or aggregate through SQLite3::Database#create_function, #create_aggregate or #create_aggregate_handler - a common pattern for adding helpers such as a hashing, formatting or scoring function.",
        "Find any request path that causes that function to be evaluated over a column whose value the attacker can write, for example a file-upload, avatar, attachment or serialized-state column stored as a BLOB.",
        "Store a blob whose bytes contain no 0x00 terminator, for instance by binding a value wrapped in SQLite3::Blob so the native layer binds it with sqlite3_bind_blob and its exact length (ext/sqlite3/statement.c:231), preserving the absence of a trailing NUL.",
        "Trigger the query that invokes the custom function on that row; SQLite calls rb_sqlite3_func, which converts the blob at ext/sqlite3/database.c:250 with strlen semantics and reads past the end of the blob buffer.",
        "Read back the value the application derives from the function argument - its return value, an error message, a log line or a rendered field - and recover the adjacent heap bytes, which can include other rows, cached database pages or SQL text containing credentials.",
        "Repeat with varying blob sizes to shift the buffer's heap placement and progressively harvest different neighbouring allocations.",
        "Alternatively, store an empty blob (SQL value X'') so sqlite3_value_blob returns NULL, making the conversion dereference a NULL pointer and crash the worker process for a denial of service."
      ],
      "preconditions": [
        "The application registers at least one custom SQL function or aggregate via Database#create_function, #create_aggregate, #create_aggregate_handler, #define_function or #define_aggregator; the vulnerable trampoline is only reached through these callbacks.",
        "That function or aggregate is evaluated with at least one BLOB-typed argument, which the attacker achieves by controlling stored blob data or by influencing the SQL enough to pass a blob literal.",
        "The application surfaces something derived from the argument value back to the attacker (return value, log, error, or rendered output) for the disclosure variant; the NULL-dereference denial-of-service variant needs no such observability.",
        "Ruby's rb_tainted_str_new2 resolves to the NUL-terminated constructor family that computes length with strlen, which is the documented behaviour of the _new2 / _new_cstr variants.",
        "No verification by execution was performed in this read-only review, so the over-read is established from the SQLite API contract, the Ruby API contract and the contrasting length-aware sibling code rather than from an observed crash or leaked bytes."
      ],
      "recommendations": [
        "Root-cause fix: convert values using an explicit length instead of C-string semantics - replace ext/sqlite3/database.c:250 with rb_tainted_str_new((const char *)sqlite3_value_blob(val), (long)sqlite3_value_bytes(val)), mirroring ext/sqlite3/statement.c:157, and apply the same length-aware conversion to the SQLITE_TEXT branch at ext/sqlite3/database.c:247 so embedded NUL bytes stop truncating values.",
        "Call sqlite3_value_bytes first and treat a zero length as an empty string without dereferencing the pointer, so the documented NULL return for a zero-length blob can no longer cause a NULL dereference.",
        "Hardening: audit the extension for every remaining rb_str_new2 / rb_tainted_str_new2 call that is fed a pointer originating from SQLite data rather than from a known literal, and standardise on the length-carrying constructors for all value and column conversions.",
        "Regression test: register a custom function through Database#create_function and assert that it receives byte-exact arguments for three blob inputs - a blob with no trailing NUL, a blob containing an interior NUL such as \"a\\0b\", and a zero-length blob X'' - checking both the returned bytesize and that no crash occurs; each case fails against the current code."
      ]
    },
    {
      "title": "Database#busy_handler registers its callback with sqlite3_trace, leaking heap addresses and silently disabling SQL audit tracing",
      "category": "info-disclosure",
      "file": "ext/sqlite3/database.c",
      "line": 215,
      "ruleId": "info-disclosure.callback-registration",
      "identity": {
        "anchor": "busy-handler-registration"
      },
      "symbol": "busy_handler",
      "snippet": "  int status = sqlite3_trace(",
      "severity": "LOW",
      "difficulty": "MEDIUM",
      "confidence": "MEDIUM",
      "rationale": "The busy-handler registration calls the wrong SQLite API, installing a callback typed int(void*, int) into the tracer slot that SQLite declares as void(*)(void*, const char*). SQLite consequently invokes it once per executed statement and passes the SQL text pointer in the slot the callback reads as an int count, so a live heap address is boxed into a Ruby Integer and handed to application code. The CHECK wrapper does not catch this because sqlite3_trace returns a void* previous-callback argument that is NULL on first registration and therefore reads as status 0. The same slot is used by Database#trace, so registering a busy handler silently displaces any SQL audit tracer.",
      "impact": "Database#busy_handler registers its callback with sqlite3_trace instead of sqlite3_busy_handler, so a callback typed int(void*, int) is installed where SQLite expects void(void*, const char*). SQLite therefore invokes it once per executed statement, passing the address of the SQL text buffer in the argument slot the callback reads as an int count. The low bits of a live heap pointer are then boxed into a Ruby Integer and handed to the application block, disclosing heap addresses that defeat ASLR to anyone who can observe values the block logs or returns. The same mis-registration silently overwrites any callback installed via Database#trace, so an application that relies on #trace for SQL audit logging loses its audit trail as soon as a busy handler is registered, letting subsequent attacker-submitted SQL execute unlogged; the busy handler itself never runs, so the contention behaviour the application configured is absent as well.",
      "evidence": [
        "lib/sqlite3/database.rb:36 - Database includes Pragmas and exposes the native methods defined below, so the busy_handler method registered in the extension is reachable as ordinary public API on the in-scope Ruby Database object.",
        "ext/sqlite3/database.c:201 - busy_handler is the public entry point, bound as the Ruby method \"busy_handler\" at ext/sqlite3/database.c:591; it accepts a block or callable object from the application.",
        "ext/sqlite3/database.c:215 - ROOT CONTROL: the registration calls sqlite3_trace rather than sqlite3_busy_handler, so the busy-handler callback is installed into the tracer slot.",
        "ext/sqlite3/database.c:216 - rb_sqlite3_busy_handler is passed as that tracer callback, binding a function of type int(void*, int) into a slot SQLite declares as void(*xTrace)(void*, const char*).",
        "/usr/include/sqlite3.h:3342 - sqlite3_trace is declared as taking void(*xTrace)(void*, const char*), while /usr/include/sqlite3.h:2861 declares sqlite3_busy_handler as taking int(*)(void*, int); the two signatures differ in both the second parameter type and the return type, confirming the mismatch rather than a harmless alias.",
        "ext/sqlite3/database.c:176 - rb_sqlite3_busy_handler declares its second parameter as int count, so when SQLite invokes it as a tracer it receives the const char *sql pointer in that argument slot and interprets the pointer's low bits as an integer.",
        "ext/sqlite3/database.c:180 - SINK: rb_funcall(handle, rb_intern(\"call\"), 1, INT2NUM((long)count)) boxes those pointer-derived bits into a Ruby Integer and passes them to the application-supplied block, moving a heap address across the native-to-Ruby boundary.",
        "Guard check (ineffective): ext/sqlite3/database.c:218 wraps the result in CHECK, but CHECK expands via ext/sqlite3/exception.h:4 to rb_sqlite3_raise(_db, _status), which returns immediately for SQLITE_OK per ext/sqlite3/exception.c:8. sqlite3_trace returns the previous callback argument as a void*, which is NULL on the first registration and therefore reads as status 0, so the check passes silently and never flags the wrong-API call.",
        "ext/sqlite3/database.c:171 - Database#trace installs tracefunc into the very same sqlite3_trace slot, so the two registrations overwrite one another; whichever is called last wins, and @tracefunc set at ext/sqlite3/database.c:169 remains populated while never being invoked, which is why the loss of audit logging is silent.",
        "ext/sqlite3/database.c:146 - the intended tracer, which forwards every executed SQL statement to the Ruby callback, is the audit sink that stops receiving statements once busy_handler displaces it."
      ],
      "exploitScenarios": [
        "Find an application that calls SQLite3::Database#busy_handler, a common configuration step for handling database contention under concurrency.",
        "Observe any output derived from the block's argument - most busy handlers log or return the retry count, for example in a warning line or an exposed metric.",
        "Submit any request that executes SQL, since the mis-registered callback fires once per statement rather than only on contention, producing a value on demand.",
        "Read the reported count and recover the low bits of the SQL text buffer's heap address, then repeat across requests to map allocation behaviour and defeat ASLR as a stepping stone for a memory-corruption exploit such as the blob over-read in this same extension.",
        "Separately, in an application that installs Database#trace for SQL audit logging and later calls #busy_handler, note that the tracer is displaced and audit records stop; submit further SQL knowing it will not appear in the audit trail."
      ],
      "preconditions": [
        "The application calls Database#busy_handler with a block or callable; the defect is dormant until a busy handler is registered.",
        "For the address-disclosure effect, the application must surface a value derived from the block's argument to the attacker via a log, metric, error or response field.",
        "For the audit-gap effect, the application must also rely on Database#trace for logging and must register the busy handler after the tracer.",
        "The platform calling convention must pass the pointer in the argument register the callee reads as an int, which holds on mainstream ABIs such as x86-64 SysV; passing arguments through an incompatible function pointer type is undefined behaviour, so the precise observable value is platform-dependent.",
        "No execution was performed in this read-only review, so the disclosed value's exact content is inferred from the declared signatures and calling convention rather than observed."
      ],
      "recommendations": [
        "Root-cause fix: register the callback with the correct API - change ext/sqlite3/database.c:215 to call sqlite3_busy_handler(ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self), which matches rb_sqlite3_busy_handler's int(void*, int) signature and stops both the pointer-as-count disclosure and the clobbering of the tracer.",
        "Correct the status handling at the same site: sqlite3_trace returns void*, so assigning it to int and feeding it to CHECK is meaningless; capture the int return of sqlite3_busy_handler instead so a real registration failure is raised.",
        "Hardening: build the extension without suppressing pointer-to-int and incompatible-function-pointer diagnostics and treat them as errors, since the existing -Wall in ext/sqlite3/extconf.rb:9 already had the information needed to catch this and it was not acted on.",
        "Regression test: install a tracer with Database#trace and then a handler with Database#busy_handler, execute a simple statement, and assert both that the tracer still receives the SQL text and that the busy-handler block is not invoked by ordinary non-contended statements; also assert the handler's argument is a small retry counter rather than a large pointer-sized integer. Each assertion fails against the current code."
      ]
    }
  ]
}