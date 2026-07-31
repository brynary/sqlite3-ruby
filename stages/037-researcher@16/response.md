Ruby and mkmf are not installed in this container, so everything below is from static reading; I ran no builds. Let me record my verified reachability facts before writing up.

I verified three facts that eliminated most of the supplied threat model:

- `tasks/*.rake` are **not loaded**. The current `Rakefile` (32 lines) has no `import`; commit `fb1c2b1` deleted `Dir['tasks/*.rake'].sort.each { |f| import f }`, and there is no `rakelib/` directory (rake's default auto-load path). `tasks/native.rake:5` also targets `ext/sqlite3_api`, which does not exist. So the plain-HTTP `wget`/`unzip`/`dlltool` chain is orphaned code.
- `setup.rb:1074`'s shell interpolation is fed by `@options['config-opt'] = ARGV.dup` (`setup.rb:747`) during the unprivileged `config` task, and `config-opt` is never persisted into `.config` (`save` at `setup.rb:289` writes only the `ConfigTable`). Same-user self-injection, no privilege crossing.
- `ENV['CC']` at `extconf.rb:7` is set by whoever launches the build; controlling it already implies controlling that process.

```json
{
  "findings": [
    {
      "file": "ext/sqlite3/extconf.rb",
      "line": 12,
      "ruleId": "privilege-escalation.library-search-path",
      "identity": {
        "anchor": "sqlite3-dir-config-defaults"
      },
      "category": "privilege-escalation",
      "severity": "MEDIUM",
      "difficulty": "HIGH",
      "confidence": "MEDIUM",
      "title": "Hardcoded /opt/local include and library defaults are prepended to the extension's build and runtime search path with no ownership or provenance check",
      "rationale": "extconf.rb:12 supplies '/opt/local/include' and '/opt/local/lib' as the mkmf dir_config defaults for --with-sqlite3-include and --with-sqlite3-lib. Because they are defaults rather than platform-gated hints, they take effect on every platform whenever the installer runs the documented plain 'gem install sqlite3-ruby' with no --with-sqlite3-* flag, and mkmf prepends them ahead of the system directories. The header probe at line 19 and the library probe at line 20 therefore resolve /opt/local first, and the only test applied to the selected library is that it exports sqlite3_libversion_number. Nothing canonicalizes the paths, checks that they exist, checks who owns them, asserts a minimum SQLite version, or checks that the header found and the library found describe the same library. create_makefile at line 26 then bakes those search paths into the Makefile that make executes with installer privileges, and on ELF targets mkmf's libpathflag emits an -Wl,-R rpath alongside -L, so the directory is also consulted by the dynamic loader in every process that later requires the extension. The decision of which libsqlite3 becomes the gem's SQL parser and storage engine is thus delegated to a fixed filesystem location that the code never validates.",
      "evidence": [
        "ext/sqlite3/extconf.rb:12 - calls dir_config 'sqlite3' with '/opt/local/include' and '/opt/local/lib' as the idefault/ldefault arguments; in mkmf these become the fallback values of --with-sqlite3-include and --with-sqlite3-lib, so they are applied unconditionally on all platforms (not just MacPorts hosts) when the installer supplies no flag, and mkmf prepends them ahead of the system include and library directories rather than appending them.",
        "README.rdoc:26 - documents 'gem install sqlite3-ruby' with no --with-sqlite3-* argument as the normal installation command, which is exactly the path on which the unvalidated hardcoded defaults are in force; the flag form at README.rdoc:30 is presented only as the non-standard-location alternative.",
        "Rakefile:18 - registers ext/sqlite3/extconf.rb in spec_extras[:extensions], so this script runs automatically during gem installation, commonly under sudo or as a root-owned system gem install, giving the build a higher privilege level than a local unprivileged attacker.",
        "ext/sqlite3/extconf.rb:19 - find_header 'sqlite3.h' compiles a probe using the accumulated CPPFLAGS from line 12; first match wins, so a /opt/local/include/sqlite3.h shadows /usr/include/sqlite3.h. Guard checked: there is no existence, canonicalization, symlink, or ownership check on the directory before it is trusted as an include path.",
        "ext/sqlite3/sqlite3_ruby.h:21 - '#include <sqlite3.h>' resolves through that poisoned include path for every C source (each of ext/sqlite3/sqlite3.c, database.c, statement.c, exception.c includes sqlite3_ruby.h at line 1), so a substituted header can redefine the struct layouts and macros the extension is compiled against.",
        "ext/sqlite3/extconf.rb:20 - find_library 'sqlite3', 'sqlite3_libversion_number' links the probe against the first libsqlite3 found on the prepended $LIBPATH, making this the decision point for which library the whole gem binds to. Guard checked and found ineffective: the sole test is that the candidate exports sqlite3_libversion_number, which any attacker-supplied shared object can export; there is no minimum version assertion, no signature or package-manager provenance check, and no check that the header from line 19 and this library agree.",
        "ext/sqlite3/extconf.rb:26 - create_makefile('sqlite3_native') writes those include and library search paths into the generated Makefile, which make subsequently executes with installer privileges and with no re-validation of any path; on ELF targets mkmf's libpathflag pairs each -L entry with an -Wl,-R rpath entry, persisting /opt/local/lib into the built object as a runtime search directory.",
        "lib/sqlite3.rb:1 - \"require 'sqlite3/sqlite3_native'\" loads that built object into every consumer Ruby process, so a build-time substitution, or a runtime resolution through the embedded rpath entry, executes attacker-controlled native code in the address space of every application using this gem."
      ],
      "snippet": "sqlite    = dir_config 'sqlite3', '/opt/local/include', '/opt/local/lib'",
      "symbol": "(extconf.rb top-level script body)",
      "impact": "An attacker able to place files in /opt/local/lib or /opt/local/include gets their code chosen as the gem's SQLite implementation ahead of the system library. At build time that yields arbitrary native code compiled and linked into sqlite3_native, executed with the privileges of the install (frequently root under sudo gem install), which is local privilege escalation. Because the directory is also persisted as a runtime search entry in the built object on ELF targets, the substituted library is loaded into every process that requires the gem afterwards, converting one writable directory into arbitrary code execution and full read/write access to every SQLite database those applications open. A silently mismatched or backdoored libsqlite3 satisfies the only probe the script performs, so neither the installer nor consumers get any signal that the trust base changed.",
      "exploitScenarios": [
        "The attacker identifies a host where /opt/local/lib is writable by their account, or where /opt itself is writable so they can create /opt/local/lib, while system gems are installed by a more privileged account.",
        "The attacker writes a malicious libsqlite3.so into /opt/local/lib that exports sqlite3_libversion_number so it satisfies the probe at ext/sqlite3/extconf.rb:20, and optionally a matching sqlite3.h into /opt/local/include to satisfy ext/sqlite3/extconf.rb:19.",
        "The attacker waits for, or induces via a support request or provisioning script, the documented privileged install 'sudo gem install sqlite3-ruby' with no --with-sqlite3-* flag, which is the README.rdoc:26 path.",
        "extconf.rb:12 prepends the attacker's directories ahead of the system paths, so find_header and find_library select the attacker's header and library instead of the packaged ones, and no version, provenance, or header-versus-library consistency check rejects them.",
        "create_makefile at ext/sqlite3/extconf.rb:26 bakes those paths into the Makefile, and make links the attacker's library into sqlite3_native while running with the installer's elevated privileges, executing the attacker's build-time code in that context.",
        "Every later process that reaches lib/sqlite3.rb:1 loads the resulting object; on ELF targets the embedded rpath entry also causes the dynamic loader to prefer /opt/local/lib at load time, so the attacker's code runs inside each consuming application and mediates all of its database reads and writes."
      ],
      "preconditions": [
        "The attacker can write into /opt/local/lib or /opt/local/include, or can create /opt/local because /opt is writable by them. This is not the default on stock Linux or macOS, where /opt is root-owned and mode 0755, so filesystem permissions are the only real defense standing between this code and exploitation; the precondition requires a misconfigured host, a container image that loosens /opt, or a CI or provisioning account that owns /opt.",
        "The install runs without --with-sqlite3-dir, --with-sqlite3-include, or --with-sqlite3-lib, which is the documented default command at README.rdoc:26; supplying an explicit path suppresses the hardcoded defaults.",
        "For privilege escalation specifically, the gem build must run at a higher privilege than the attacker, such as sudo gem install or a root-owned system gem path.",
        "For the runtime-loader half of the impact, the target platform must be one where mkmf pairs -L with an -Wl,-R rpath entry; I could not execute mkmf or inspect a generated Makefile in this environment, so this part of the chain is reasoned from mkmf's libpathflag behavior rather than observed, which is why confidence is MEDIUM rather than HIGH."
      ],
      "recommendations": [
        "Root-cause fix: stop passing hardcoded filesystem defaults to dir_config. Call dir_config 'sqlite3' with no default arguments and let the compiler's and linker's configured search paths, or pkg-config, locate the library, so that a non-system directory is only ever searched when the installer explicitly asks for it.",
        "If a platform hint is genuinely wanted for MacPorts, gate it on RUBY_PLATFORM matching darwin and on the directory actually existing, and append it after the system paths instead of prepending it, so a system-packaged SQLite always wins.",
        "Harden the acceptance test at ext/sqlite3/extconf.rb:20 beyond an exported-symbol probe: assert a minimum SQLITE_VERSION_NUMBER and verify that the header located by find_header and the library located by find_library report the same version, so a mismatched or substituted library aborts the build instead of being accepted silently.",
        "Avoid persisting caller-supplied or defaulted library directories as rpath entries in the shipped object, for example by filtering RPATHFLAG for non-system paths, so a build-time search path cannot become a permanent runtime search path in consumer processes.",
        "Regression test: add a build test that runs extconf.rb with no --with-sqlite3-* flags inside a sandbox containing a decoy /opt/local/include/sqlite3.h and /opt/local/lib/libsqlite3 that exports sqlite3_libversion_number, then asserts that the generated Makefile contains no /opt/local -I, -L, or -R entry and that the decoy was not selected."
      ],
      "cweId": "CWE-426"
    }
  ]
}
```

**One finding, at `ext/sqlite3/extconf.rb:12`.** The script hands mkmf `/opt/local/include` and `/opt/local/lib` as `dir_config` *defaults*, so they apply on every platform during the documented flagless `gem install`, are prepended ahead of the system directories, and are never checked for existence or ownership. The only test applied to whatever library is found is that it exports `sqlite3_libversion_number` (line 20) — no version, provenance, or header/library agreement check — and `create_makefile` (line 26) bakes the result into a Makefile that `make` runs with installer privileges. I rated it MEDIUM severity with HIGH difficulty because the attack needs write access to a location that is root-owned on stock systems; filesystem permissions on `/opt`, not this code, are what normally stop it.

Confidence is MEDIUM, not HIGH, for a specific reason: Ruby is not installed in this container, so I could not run `extconf.rb` or inspect a generated Makefile. The claim that `dir_config` defaults take effect absent a flag, and that mkmf's `libpathflag` pairs `-L` with an `-Wl,-R` rpath entry on ELF targets, rests on mkmf semantics rather than observed output. The rpath detail is what extends the impact from build time into every consumer process, so it is the part most worth confirming against a real build.

Three supplied leads I checked and rejected, with evidence:

- **Plain-HTTP vendored SQLite download** (`tasks/vendor_sqlite3.rake:36,39,59`) — unreachable in this tree. `Rakefile` has no `import`; commit `fb1c2b1` removed `Dir['tasks/*.rake'].sort.each { |f| import f }`, and there is no `rakelib/`, which is rake's only auto-load directory. `tasks/native.rake:5` also builds `ext/sqlite3_api`, a directory that does not exist. The files ship via `Manifest.txt` but are never loaded, so there is no live flow into `extconf.rb`.
- **`ENV['CC']` → Makefile compiler** (`extconf.rb:7`) — no privilege boundary is crossed. Whoever sets the environment of the build process already controls that process.
- **`setup.rb:1074` unquoted interpolation** — `@options['config-opt']` comes from `ARGV.dup` (`setup.rb:747`) during the unprivileged `config` task and is never written to `.config` (`save` at `setup.rb:289` persists only the `ConfigTable`), so it cannot reach the privileged `install` step. I also traced the `.config`-planting variant into `exec_install`: it would give root-owned arbitrary file writes via `config('so-dir')` at `setup.rb:1151`, but writing `.config` requires write access to the build tree, which equally permits editing `setup.rb` or dropping a `metaconfig`/hook file that is `instance_eval`'d at `setup.rb:322` and `setup.rb:522`. It is not a distinct control failure.

No prompt-injection finding: there are no agent-instruction files in the tree, and a grep across repository content for agent-steering phrasing returned nothing.