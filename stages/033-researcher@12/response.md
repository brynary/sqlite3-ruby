{
  "findings": [
    {
      "title": "Unvalidated database values passed to unbounded Date/Time parsers in SQLite3::Translator",
      "category": "injection-and-input",
      "file": "lib/sqlite3/translator.rb",
      "line": 66,
      "symbol": "register_default_translators",
      "ruleId": "redos.type-translation",
      "identity": {
        "anchor": "type-translation-coercion"
      },
      "severity": "MEDIUM",
      "difficulty": "LOW",
      "confidence": "MEDIUM",
      "snippet": "        \"timestamp\" ].each { |type| add_translator( type ) { |t, v| Time.parse( v ) } }",
      "rationale": "This is the one candidate in the component with a complete, unguarded path from an untrusted source to a dangerous operation. Row bytes enter Ruby verbatim from the C step function with no length bound (ext/sqlite3/statement.c:145), travel through ResultSet#next (lib/sqlite3/resultset.rb:71) into Translator#translate, whose only guard is `unless value.nil?` (lib/sqlite3/translator.rb:46), and are dispatched on the database-supplied decltype straight into Time.parse / Date.parse / DateTime.parse. There is no length cap, no String type check, and a grep for `rescue` across lib/ finds only Database#transaction (lib/sqlite3/database.rb:431), so nothing on the path degrades gracefully. By contrast the more obvious-looking SQL construction sinks in this component are not reported: `\"PRAGMA table_info(#{table})\"` (lib/sqlite3/pragmas.rb:220) and the hand-rolled quote wrapping (lib/sqlite3/pragmas.rb:51) reach sqlite3_prepare_v2 (ext/sqlite3/statement.c:53), which compiles only the first statement and parks the rest in @remainder (ext/sqlite3/statement.c:64); no pragma path ever executes that remainder, and the SQLite PRAGMA grammar admits a single token in the value position, so an injected identifier yields either the intended table lookup or a parse error, not a subquery or a second statement. Without a demonstrable dangerous operation those are unsafe-looking APIs rather than findings.",
      "impact": "An attacker who can write a single row into a column declared time/timestamp/date/datetime (or bit/bool/boolean) can poison every subsequent read of that table for every user of the application. The stored bytes are handed verbatim and unbounded to Ruby's heuristic date parsers with no length cap, no String type check, and no rescue anywhere on the path. On Ruby versions whose bundled date predates the CVE-2021-41817 fix, Date._parse backtracks catastrophically on crafted input and pegs a core; because MRI does not release the GVL during Onigmo matching, the whole process stalls rather than just the calling thread. On patched date the 128-byte parse limit converts the same input into an ArgumentError that propagates uncaught out of an ordinary row read. Either way the damage is persistent until the row is deleted, and it is triggered by a normal SELECT rather than by any privileged action.",
      "evidence": [
        "ext/sqlite3/statement.c:145 — a SQLITE_TEXT column value is copied into a Ruby String with rb_tainted_str_new using sqlite3_column_bytes as the length, so whatever bytes an attacker stored in the row reach Ruby verbatim with no length bound or content check.",
        "ext/sqlite3/statement.c:342 — the sibling column_decltype method returns sqlite3_column_decltype, i.e. the declared type text from the database file's schema, which SQLite does not guarantee matches the actual storage class of the value.",
        "lib/sqlite3/resultset.rb:66 — ResultSet#next calls @stmt.step, obtaining that untrusted row array straight from the C step function above.",
        "lib/sqlite3/resultset.rb:69 — the only gate on the whole translation path is the truthiness of @db.type_translation; lib/sqlite3/database.rb:57 shows it is a plain attr_accessor, so this is an application opt-in switch and performs no validation of the data whatsoever.",
        "lib/sqlite3/resultset.rb:70 — zips each row value against @stmt.types, pairing attacker-controlled data with the schema-declared type; this is the point where a value whose storage class disagrees with its decltype gets routed to a parser built for the decltype.",
        "lib/sqlite3/resultset.rb:71 — passes the raw type and raw value into Translator#translate; no length check, no type check, and no begin/rescue around the call.",
        "lib/sqlite3/translator.rb:46 — the sole guard inside translate is `unless value.nil?`; it excludes only NULL, so every non-nil String, Integer, Float and BLOB proceeds regardless of size or class.",
        "lib/sqlite3/translator.rb:47 — @translators[type_name(type)].call(type, value) dispatches on the database-supplied decltype string, so the schema selects which coercion runs on the attacker's bytes.",
        "lib/sqlite3/translator.rb:66 — for decltypes `time` and `timestamp` the selected proc is Time.parse(v), which routes through Date._parse; this is the sink, invoked on unbounded untrusted text.",
        "lib/sqlite3/translator.rb:68 — the same pattern registers Date.parse(v) for `date`, and lib/sqlite3/translator.rb:69 registers DateTime.parse(v) for `datetime`; all three are the same unbounded-parser sink under this one root control.",
        "lib/sqlite3/translator.rb:89 — the bit/bool/boolean translator calls v.strip.gsub(/00+/,\"0\") assuming v is a String, so a value stored with INTEGER or BLOB storage class in a bool-declared column raises NoMethodError out of the same read path; downstream effect of the same missing validation.",
        "lib/sqlite3/statement.rb:104 — Statement#each calls the C step directly, so Database#execute (lib/sqlite3/database.rb:115 and :137) and ResultSet#each (lib/sqlite3/resultset.rb:97) bypass the translator entirely; this is why the exploit requires ResultSet#next, and it is the one real constraint on reachability rather than a defense against the malformed input.",
        "lib/sqlite3/translator.rb:1-109 — a grep for rescue across lib/ returns only lib/sqlite3/database.rb:431 (inside Database#transaction); there is no exception handling and no length or class validation at any hop between the C string creation and the parser call, so nothing on the path degrades gracefully."
      ],
      "exploitScenarios": [
        "The application enables the opt-in feature Database#type_translation = true (lib/sqlite3/database.rb:57).",
        "The application has a column declared `timestamp` (or `time`, `date`, `datetime`) and writes user-supplied text into it, for example `db.execute(\"insert into events (occurred_at) values (?)\", params[:when])`.",
        "The attacker submits a multi-kilobyte non-numeric string shaped for date-format backtracking; because a `timestamp` declaration carries NUMERIC affinity, SQLite stores non-numeric text unchanged as TEXT, so the payload survives the write intact.",
        "Any later read that materializes the row through ResultSet#next — the only translating iteration path, e.g. `db.query(\"select * from events\") { |r| while row = r.next; ...; end }` — reaches lib/sqlite3/resultset.rb:71.",
        "translate dispatches on the `timestamp` decltype and calls Time.parse on the payload (lib/sqlite3/translator.rb:66) with no length limit.",
        "On a Ruby whose date library predates the CVE-2021-41817 fix, Date._parse backtracks catastrophically and consumes CPU while holding the MRI GVL, stalling the process; on a patched date the 128-byte limit raises ArgumentError instead, which propagates uncaught out of the row read.",
        "The attacker needed one write: every subsequent read of that table through ResultSet#next stalls or raises for all users until the poisoned row is removed. The same effect is reachable with an integer written into a bool-declared column, hitting the v.strip sink at lib/sqlite3/translator.rb:89."
      ],
      "preconditions": [
        "Database#type_translation must be set to true; it defaults to nil, so this is a non-default configuration.",
        "The application must iterate results with ResultSet#next, which is the only path that invokes the translator — Database#execute, Statement#each and ResultSet#each all bypass it via lib/sqlite3/statement.rb:104.",
        "A queried column must be declared with a type that maps to a coercing translator: time, timestamp, date or datetime for the parser sinks, or bit, bool or boolean for the strip sink.",
        "The attacker must be able to influence the stored value of that column (ordinary application write path), or the process must open a SQLite file the attacker supplied.",
        "For the CPU-exhaustion form specifically, the running Ruby's date library must predate the CVE-2021-41817 `limit:` fix; on newer Ruby the impact degrades to the uncaught ArgumentError described above.",
        "Confidence is MEDIUM because the code path was verified entirely by reading, and no code was executed in this review to observe the parser's behaviour on this host's Ruby and date versions."
      ],
      "recommendations": [
        "Root cause: validate the value before handing it to a parser in Translator#translate — require `String === value` and enforce a maximum byte length, and pass an explicit `limit:` to the Date/Time parse calls; when the actual storage class disagrees with the declared type, return the value untranslated instead of coercing it.",
        "Hardening: wrap each default translator so that a parse or coercion failure yields the raw value rather than propagating an exception out of a row read, and prefer explicit formats (Date.strptime / Time.strptime) over the heuristic parse family for schema-declared types.",
        "Regression test: with type_translation enabled, insert into a `timestamp` column (a) a multi-kilobyte non-date string and (b) an integer, plus an integer into a `bool` column, then read each row via ResultSet#next and assert it returns without raising and inside a fixed wall-clock budget."
      ]
    }
  ]
}