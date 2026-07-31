{
  "findings": [
    {
      "title": "Use-after-free and double free: SQLite3::Statement#close finalizes the statement before nulling the handle, so a failing close leaves a dangling sqlite3_stmt that all closed? guards report as open",
      "category": "memory",
      "ruleId": "use-after-free.statement-handle-lifetime",
      "identity": {
        "anchor": "statement-close-finalize-ordering"
      },
      "file": "ext/sqlite3/statement.c",
      "line": 85,
      "symbol": "sqlite3_rb_close",
      "snippet": "  CHECK(db, sqlite3_finalize(ctx->st));",
      "severity": "HIGH",
      "difficulty": "MEDIUM",
      "confidence": "HIGH",
      "rationale": "sqlite3_finalize() is evaluated as the CHECK macro argument, so the statement is deallocated before rb_sqlite3_raise decides whether to longjmp. Per /usr/include/sqlite3.h, finalize frees the statement unconditionally but returns the deferred error code of the most recent failed step, so any attacker-triggerable step failure (SQLITE_CONSTRAINT from submitted data, SQLITE_BUSY from a concurrent writer) makes CHECK raise after the free and skip 'ctx->st = NULL' on the next line. The struct field keeps a pointer to freed memory, and every open/closed predicate in the gem tests only '!ctx->st', so REQUIRE_OPEN_STMT, closed_p, ResultSet#closed? and Statement#must_be_open! all report the freed statement as open. The gem itself supplies the second close: Database#query has an unconditional 'ensure result.close' while its own documentation instructs callers to close the ResultSet too. The path is complete from untrusted SQL/bind data to a use-after-free read and a double sqlite3_finalize, with no effective defense at any hop. Confidence is HIGH because every hop is verified in source and against the installed SQLite header; exploitation beyond a crash was not executed, which is reflected in difficulty rather than confidence.",
      "impact": "A failing SQLite3::Statement#close leaves ctx->st pointing at a sqlite3_stmt that libsqlite3 has already deallocated, while every closed? guard in the gem still reports the statement as open. Any later use of that statement object dereferences freed heap memory, and a second close calls sqlite3_finalize() on the freed pointer, which is a double free. sqlite3.h states that use of a finalized statement 'can result in undefined and undesirable behavior such as segfaults and heap corruption'. An attacker who can induce a step error on a statement the application still holds gets a remotely triggerable heap-corruption primitive in-process, and at minimum a reliable crash of the Ruby VM. Because the error is deferred and re-reported by finalize, the exact failure the attacker causes (a UNIQUE constraint violation from submitted data, or SQLITE_BUSY from a concurrent writer) is what arms the bug.",
      "evidence": [
        "lib/sqlite3/database.rb:201 - Database#query is a public API that prepares and executes caller-supplied SQL with caller-supplied bind values; it is the untrusted entry point that reaches the vulnerable control.",
        "lib/sqlite3/statement.rb:65 - Statement#execute stores '@results = ResultSet.new(@connection, self)', and lib/sqlite3/resultset.rb:36 stores '@stmt = stmt', so the Statement object outlives the query frame and stays reachable from caller code after any exception.",
        "ext/sqlite3/statement.c:127 - 'int value = sqlite3_step(stmt);' returns the engine result for the attacker-influenced operation; attacker data that violates a UNIQUE or NOT NULL column yields SQLITE_CONSTRAINT, and a concurrent writer yields SQLITE_BUSY. Because the statement was prepared with sqlite3_prepare_v2 (statement.c:53), the specific code is returned directly.",
        "ext/sqlite3/statement.c:178 - the step switch default branch 'CHECK(sqlite3_db_handle(ctx->st), value);' forwards that non-OK code, raising a Ruby exception out of Statement#step and beginning stack unwinding with the statement still open.",
        "lib/sqlite3/database.rb:206 - the 'ensure' clause of Database#query runs during that unwinding and calls 'result.close' at line 207; lib/sqlite3/resultset.rb:104 delegates straight to '@stmt.close'. This is an unconditional close with no closed? guard.",
        "ext/sqlite3/statement.c:82 - 'REQUIRE_OPEN_STMT(ctx);' is the only guard on the close path, and its definition at statement.c:3-5 tests solely 'if(!_ctxt->st)'. It is checked and ineffective against a stale non-NULL pointer.",
        "ext/sqlite3/statement.c:85 - 'CHECK(db, sqlite3_finalize(ctx->st));' is the root control. sqlite3_finalize deallocates the statement unconditionally, yet /usr/include/sqlite3.h documents 'If the most recent evaluation of statement S failed, then sqlite3_finalize(S) returns the appropriate error code or extended error code', so the deferred SQLITE_CONSTRAINT or SQLITE_BUSY is returned here after the free has already happened.",
        "ext/sqlite3/exception.h:4 - '#define CHECK(_db, _status) rb_sqlite3_raise(_db, _status);' calls the raiser unconditionally, with the freeing sqlite3_finalize() call evaluated as the macro argument.",
        "ext/sqlite3/exception.c:8 - rb_sqlite3_raise returns early only for exact equality with SQLITE_OK; every other status falls through to exception.c:93 'rb_raise(klass, \"%s\", sqlite3_errmsg(db));', a non-local longjmp.",
        "ext/sqlite3/statement.c:87 - 'ctx->st = NULL;' sits after the CHECK and is therefore skipped by the longjmp. The struct field (ext/sqlite3/statement.h:7) retains a pointer to freed memory. This ordering is the root cause.",
        "ext/sqlite3/statement.c:101 - closed_p returns Qtrue only when 'if(!ctx->st)', so Statement#closed?, ResultSet#closed? (lib/sqlite3/resultset.rb:109) and Statement#must_be_open! (lib/sqlite3/statement.rb:141) all report the freed statement as still open. Every application-level guard is defeated.",
        "ext/sqlite3/statement.c:84 - on a second close, 'sqlite3 * db = sqlite3_db_handle(ctx->st);' reads the freed sqlite3_stmt allocation before statement.c:85 calls sqlite3_finalize on it again, producing the use-after-free read and the double free.",
        "ext/sqlite3/statement.c:9 - the GC free function 'deallocate' only performs 'xfree(c)' and never finalizes, and ext/sqlite3/database.c:16 sweeps via sqlite3_next_stmt which no longer lists the already-freed statement, so nothing reclaims or neutralizes the dangling pointer.",
        "git blame ext/sqlite3/statement.c -L 84,87 - lines 84-85 are commit da74b8e ('centralizing exception handling, removing dead code') and line 87 is cd7ae9d ('statement closing works now'); the raise-before-null-out ordering has existed since the C rewrite and no commit has ever reordered it or added a null-out on the error path."
      ],
      "exploitScenarios": [
        "The victim application calls Database#query (lib/sqlite3/database.rb:201) with a block, or Database#prepare without a block (lib/sqlite3/database.rb:84), so a Statement or ResultSet reference survives the call.",
        "The attacker supplies input that makes sqlite3_step return a non-OK code, for example a value that duplicates a UNIQUE column to force SQLITE_CONSTRAINT, or opens a concurrent write transaction to force SQLITE_BUSY.",
        "statement.c:178 raises that code out of Statement#step, unwinding the stack while ctx->st is still set.",
        "The unwinding runs the ensure clause at lib/sqlite3/database.rb:207, which calls close on the same statement.",
        "REQUIRE_OPEN_STMT at statement.c:82 passes, and sqlite3_finalize at statement.c:85 frees the statement and returns the same deferred error code.",
        "CHECK raises again via exception.c:93, so statement.c:87 never executes and ctx->st keeps the freed pointer while closed? still reports false.",
        "The attacker triggers one more operation on the retained object, either a second close (the documented caller-side close at lib/sqlite3/database.rb:197-200 plus the library's own ensure gives exactly two closes) or any method such as step, bind_param, columns or types, all of which pass the ineffective REQUIRE_OPEN_STMT guard.",
        "sqlite3_db_handle and sqlite3_finalize operate on freed heap memory, corrupting the SQLite/malloc heap or crashing the process; with repeated triggers the attacker grooms the freed chunk to control the memory that the second finalize writes through."
      ],
      "preconditions": [
        "The application retains a reference to a Statement or ResultSet past an operation that raised, which the gem's own Database#query ensure path and the no-block Database#prepare and Database#query return paths all produce.",
        "The attacker can influence data or concurrency such that sqlite3_step returns a non-OK result code, for example SQLITE_CONSTRAINT from submitted data, SQLITE_BUSY from a concurrent writer, or SQLITE_CORRUPT/SQLITE_IOERR from a hostile or damaged database file.",
        "The application catches or otherwise survives the first exception and reaches a second use or second close of the same statement object, which the documented close contract at lib/sqlite3/database.rb:197-200 actively encourages.",
        "Turning the double free into anything beyond a crash additionally requires heap grooming of the libsqlite3 allocator, which needs product knowledge and favorable allocation timing."
      ],
      "recommendations": [
        "Root-cause fix: clear the handle before it can be reported as an error. In sqlite3_rb_close, capture the pointer, null out ctx->st first, then finalize and check, for example 'sqlite3_stmt *st = ctx->st; ctx->st = NULL; sqlite3 *db = sqlite3_db_handle(st); CHECK(db, sqlite3_finalize(st));' so the raise cannot leave a dangling pointer behind.",
        "Apply the same ordering to the identical pattern in Database#close at ext/sqlite3/database.c:107, where 'CHECK(db, sqlite3_close(ctx->db));' precedes 'ctx->db = NULL;' at database.c:109.",
        "Hardening: stop embedding side-effecting, resource-releasing calls in the CHECK macro argument (ext/sqlite3/exception.h:4), and parenthesize the macro arguments, so the release and the error check are visibly separate statements at every callsite.",
        "Hardening: make the Statement GC free function at ext/sqlite3/statement.c:9-13 the single owner of finalization, and track a separate explicit 'closed' flag rather than overloading the raw pointer as the open/closed predicate used by closed_p (statement.c:101) and REQUIRE_OPEN_STMT (statement.c:3-5).",
        "Regression test: prepare a statement against a table with a UNIQUE constraint, step it into SQLITE_CONSTRAINT so close raises, then assert that stmt.closed? is true and that a second stmt.close and a stmt.step both raise the ordinary 'cannot use a closed statement' error rather than touching freed memory. Run it under valgrind or ASAN so a regression surfaces as a use-after-free report instead of passing silently."
      ]
    },
    {
      "title": "Function-pointer type confusion: Database#busy_handler registers an int(void*,int) callback through sqlite3_trace, so no busy handler is installed and the block is invoked as a tracer on every statement",
      "category": "memory",
      "ruleId": "type-confusion.callback-registration",
      "identity": {
        "anchor": "busy-handler-registration"
      },
      "file": "ext/sqlite3/database.c",
      "line": 215,
      "symbol": "busy_handler",
      "snippet": "  int status = sqlite3_trace(\n      ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self);",
      "severity": "MEDIUM",
      "difficulty": "LOW",
      "confidence": "HIGH",
      "rationale": "The registration calls the wrong libsqlite3 API, installing a callback declared 'int (*)(void *, int)' into a slot whose declared type is 'void (*)(void *, const char *)'. sqlite3_busy_handler is never referenced anywhere in the extension, so the retry protection the application asked for is simply absent, and libsqlite3 instead calls the mismatched pointer as a tracer for every executed statement, reinterpreting a const char* SQL pointer as the integer count handed to user Ruby code. Calling through an incompatible function-pointer type is undefined behavior and is rejected outright under indirect-call CFI or Windows CFG. The CHECK on the next line cannot catch the mistake because sqlite3_trace returns the previous callback pointer rather than a status code. Severity is MEDIUM because the harm is bounded to a non-default API: applications that use only busy_timeout= are unaffected, and on mainstream x86-64 the mismatch degrades to argument truncation plus missing retry rather than memory corruption. Difficulty is LOW because forcing lock contention needs only a second connection.",
      "impact": "Database#busy_handler registers its callback with sqlite3_trace() instead of sqlite3_busy_handler(), passing a function pointer of type 'int (*)(void *, int)' where libsqlite3 expects 'void (*)(void *, const char *)'. Two things follow. First, no busy handler is ever installed, so an application that explicitly asked for retry-on-contention silently gets none and fails with SQLITE_BUSY the moment any other writer holds the lock, which an attacker able to open a second connection can force at will. Second, libsqlite3 invokes the mismatched pointer as a trace callback on every statement, so the user's busy_handler block is called for every SQL statement with the low bits of the SQL text pointer reinterpreted as the integer 'count' argument. Calling a function through an incompatible function-pointer type is undefined behavior; on builds with indirect-call CFI or Windows Control Flow Guard it aborts the process, turning ordinary query execution into a denial of service. The call also clobbers any tracer installed by Database#trace, and busy_handler(nil) uninstalls that tracer rather than a busy handler.",
      "evidence": [
        "lib/sqlite3/database.rb:36 - Pragmas is mixed into Database and busy_handler is exposed to Ruby at ext/sqlite3/database.c:591 via rb_define_method(cSqlite3Database, \"busy_handler\", busy_handler, -1), so this is a public, directly callable API.",
        "ext/sqlite3/database.c:176 - 'static int rb_sqlite3_busy_handler(void * ctx, int count)' declares the callback with the busy-handler signature: it returns int and takes an int retry count.",
        "ext/sqlite3/database.c:215 - the registration calls sqlite3_trace(), not sqlite3_busy_handler(); this is the root control where the wrong API is selected.",
        "ext/sqlite3/database.c:216 - 'ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self);' passes the int(void*,int) pointer as the xTrace argument.",
        "/usr/include/sqlite3.h:3342 - the expected type is 'SQLITE_API SQLITE_DEPRECATED void *sqlite3_trace(sqlite3*, void(*xTrace)(void*,const char*), void*);', a void-returning callback whose second parameter is a const char* SQL string, which does not match the registered function.",
        "/usr/include/sqlite3.h:2861 - the API the code intended, 'SQLITE_API int sqlite3_busy_handler(sqlite3*,int(*)(void*,int),void*);', has exactly the signature of rb_sqlite3_busy_handler and is never referenced anywhere in the extension.",
        "ext/sqlite3/database.c:176 - grep across ext/ shows sqlite3_busy_handler appears only as this local function name and its use at database.c:216; the real libsqlite3 registration function is never called, confirming no busy handler is installed on any code path.",
        "ext/sqlite3/database.c:180 - when libsqlite3 invokes the pointer as a tracer, 'rb_funcall(handle, rb_intern(\"call\"), 1, INT2NUM((long)count));' converts the reinterpreted second argument, actually a const char* to the SQL text, into a Ruby Integer and passes it to the user block on every executed statement.",
        "ext/sqlite3/database.c:171 - Database#trace registers the genuine tracer 'sqlite3_trace(ctx->db, NIL_P(block) ? NULL : tracefunc, (void *)self);' on the same slot, so the two features silently overwrite each other and busy_handler(nil) at database.c:216 passes NULL and removes the tracer.",
        "ext/sqlite3/database.c:218 - 'CHECK(ctx->db, status);' checks the return of sqlite3_trace, which returns the previous callback pointer (void*) rather than a status code, so this check is meaningless and cannot detect the misregistration.",
        "test/test_integration_pending.rb:22 - the only coverage, test_busy_handler_outwait and test_busy_handler_impatient at line 53, lives in the 'pending' test file and is therefore not exercised, which is why the misregistration has gone unnoticed.",
        "git blame ext/sqlite3/database.c -L 215,218 - all four lines are commit 93ce604f (Aaron Patterson, 2010-01-24); the wrong API has been used since the feature was introduced."
      ],
      "exploitScenarios": [
        "The victim application calls db.busy_handler { |count| ... } expecting retry-on-contention, per the documented contract at ext/sqlite3/database.c:191-199.",
        "database.c:215 registers the handler through sqlite3_trace, so libsqlite3's busy-handler slot stays empty and the pointer lands in the trace slot instead.",
        "The attacker opens a second connection or process to the same database file and holds a write transaction open.",
        "The victim's next conflicting statement immediately raises SQLite3::BusyException via the step path at ext/sqlite3/statement.c:178 with no retry, denying service to a request the application was written to survive.",
        "Independently, on every statement the victim executes, libsqlite3 calls the mismatched pointer as a tracer, invoking the user's block with the truncated SQL-text pointer as 'count' and executing arbitrary application callback code on a hot path it was never meant to run on.",
        "If the extension is built with clang -fsanitize=cfi-icall or on Windows with Control Flow Guard, the indirect call through the incompatible function-pointer type is rejected and the process aborts, so any attacker who can cause one SQL statement to execute crashes the service."
      ],
      "preconditions": [
        "The application calls Database#busy_handler; applications that use only Database#busy_timeout= (ext/sqlite3/database.c:535) are unaffected because that path calls the correct API.",
        "For the availability impact, the attacker needs to create lock contention, for example a second connection or process writing to the same database file.",
        "For the process-abort impact, the extension must be built with indirect-call control-flow integrity enforcement; on a mainstream x86-64 System V build the mismatch degrades to argument truncation and the missing handler rather than memory corruption."
      ],
      "recommendations": [
        "Root-cause fix: register the callback with the matching API, replacing the sqlite3_trace call at ext/sqlite3/database.c:215-216 with 'int status = sqlite3_busy_handler(ctx->db, NIL_P(block) ? NULL : rb_sqlite3_busy_handler, (void *)self);' so the function-pointer type matches the slot and a busy handler is actually installed.",
        "Hardening: stop discarding the distinction between a status code and a returned pointer. sqlite3_trace returns the previous callback, so the CHECK at database.c:218 is checking a pointer as a status; assign each registration's result to a correctly typed variable so a future mismatch fails to compile.",
        "Hardening: build the extension with -Wincompatible-pointer-types promoted to an error, and consider -fsanitize=cfi-icall in CI, so passing an int(void*,int) where void(void*,const char*) is expected is caught at compile time rather than at runtime.",
        "Regression test: promote the busy-handler tests out of test/test_integration_pending.rb into the active suite. Hold a write lock from a second connection, assert that the block registered by db.busy_handler is actually invoked with a small monotonically increasing integer count, and assert that a block returning false produces SQLite3::BusyException while a block returning true retries. Add a separate assertion that db.busy_handler does not disturb a tracer installed by db.trace."
      ]
    }
  ]
}