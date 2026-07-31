```json
{
  "findings": [
    {
      "file": "setup.rb",
      "line": 450,
      "ruleId": "privilege-escalation.install-destination",
      "identity": {
        "anchor": "installer-privileged-install-destination"
      },
      "category": "privilege-escalation",
      "severity": "HIGH",
      "difficulty": "MEDIUM",
      "confidence": "MEDIUM",
      "title": "Root `setup.rb install` writes and chmods files at destinations taken unvalidated from the build directory's `.config`, allowing a lower-privileged local principal to escalate to root",
      "rationale": "The documented install step runs as root (setup.rb:788, README.rdoc:19-21), but it re-reads `.config` from the current working directory and trusts every key/value it finds. `ConfigTable#initialize_from_file` assigns straight into `@table` (setup.rb:285), bypassing the `config_key?` allow-list that `ConfigTable#[]=` enforces (setup.rb:297-299), and no code path ever validates that a `path`-typed value is a sane, in-prefix, non-symlinked location. `install_dir_lib` then builds its destination directly from `config('rb-dir')` (setup.rb:1146), `mkdir_p` creates the named directories as root (setup.rb:392), and `install` composes `realdest` by plain concatenation (setup.rb:443) before opening it for writing (setup.rb:450) and chmod'ing it (setup.rb:453). Every one of these operations is performed by path with no `O_NOFOLLOW`, `lstat`, or ownership check — the only `File.symlink?` call in the file (setup.rb:400) exists to *include* symlinks in deletion, not to refuse them. Because `Installer` is constructed with the source root and the object root as separate values (setup.rb:628 vs setup.rb:672), the build directory that supplies `.config` and extra install sources is a distinct trust domain from the source tree that supplies hook scripts, so this is a genuine escalation and not merely the inherent 'the source tree you install is trusted' property of an installer.",
      "evidence": [
        "README.rdoc:19 — documents the split-privilege workflow `ruby setup.rb config` / `setup` / `install`, so the configuration artifacts consumed by the final step are produced by an earlier, ordinarily unprivileged run.",
        "setup.rb:788 — the usage text states the `install` task 'may require root privilege', establishing that the code below executes as root in the normal deployment.",
        "setup.rb:1320 — `if $0 == __FILE__` entry point dispatches to `ToplevelInstaller.invoke`, so the whole chain runs from a plain `ruby setup.rb install` invocation.",
        "setup.rb:646 — `@config = load_config(task)` loads configuration for the `install` task before any installer is created.",
        "setup.rb:667 — `load_config` falls through to the `else` branch for `install`, calling `ConfigTable.load`, which unconditionally reads the on-disk `.config`.",
        "setup.rb:283 — `File.foreach(SAVE_FILE)` reads `.config` (SAVE_FILE is the relative name `'.config'`, setup.rb:204) from the *current working directory*, i.e. the build directory, not from the trusted source tree.",
        "setup.rb:285 — `@table[k] = v.strip` stores every parsed key and value with no validation; this is the root control, and it bypasses the `ConfigTable.config_key?` allow-list that setup.rb:297-299 applies on the `[]=` path, so an unexpected or hostile `rb-dir` value is accepted verbatim.",
        "setup.rb:305 — the reader `[]` only performs `$name` back-reference expansion; an absolute attacker path such as `/tmp/evil` contains no `$` and passes through unchanged, and `ConfigTable.path_config?` (setup.rb:250) is never consulted here.",
        "setup.rb:672 — `Installer.new(@config, @options, @ardir, File.expand_path('.'))` sets the object root to the current directory while the source root stays `@ardir` (setup.rb:628), confirming the build directory is a separate location from the source tree and that only the source tree supplies hook scripts (setup.rb:515).",
        "setup.rb:1146 — `install_dir_lib` builds the destination as `\"#{config('rb-dir')}/#{rel}\"`, taking the attacker-supplied `.config` value as the install directory with no normalization.",
        "setup.rb:1161 — `mkdir_p dest, @options['install-prefix']` is called with that destination; `install-prefix` defaults to the empty string (setup.rb:769) so it constrains nothing.",
        "setup.rb:392 — `Dir.mkdir path unless File.dir?(path)` creates each component of the attacker-named path as root.",
        "setup.rb:1198 — `existfiles` unions `all_files_in(curr_srcdir())` with `all_files_in('.')`, so `*.rb` files planted in the attacker-writable build directory become install sources.",
        "setup.rb:1209 — `if File.exist?(fname)   # objdir` makes `mapdir` prefer the build-directory copy over the source-tree copy, so attacker file *contents* are what get installed.",
        "setup.rb:443 — `realdest = prefix ? prefix + dest : dest` concatenates the empty prefix with the attacker-chosen directory; `''` is truthy in Ruby, so `realdest` is exactly the attacker's absolute path.",
        "setup.rb:444 — `File.dir?(realdest)` (the redefinition at setup.rb:82-84, which follows symlinks) appends `File.basename(from)`, yielding a final path inside a directory the attacker controls.",
        "setup.rb:448 — `rm_f realdest if File.exist?(realdest)` is reached whenever `diff?` (setup.rb:465-467) sees differing content; `diff?` compares bytes only and performs no path validation.",
        "setup.rb:401 — inside `rm_f`, `File.chmod 0777, fname` operates on the path and follows symlinks, so a symlink planted at `realdest` makes root chmod its *target* world-writable; the following `File.unlink` (setup.rb:402) removes only the link, leaving the 0777 mode on the victim file such as `/etc/shadow`.",
        "setup.rb:450 — `File.open(realdest, 'wb')` is the privileged sink: root writes attacker-supplied bytes to the attacker-chosen absolute path, and setup.rb:453 then chmods that path.",
        "setup.rb:441 — the only bail-out, `return if no_harm?`, depends on the operator passing `--no-harm` (setup.rb:768, setup.rb:772) and is off by default, so it is not a defense.",
        "setup.rb:1150 — `install_dir_ext` returns early because `extdir?` (setup.rb:484) requires an `ext/sqlite3/MANIFEST` that does not exist in this repository, and no `bin/` or `data/` directory exists; the `lib` traversal is therefore the live, unblocked path to the sink, and no `pre-install`/`post-install` hook files exist in the tree to interfere."
      ],
      "snippet": "      File.open(realdest, 'wb') {|f|",
      "symbol": "FileOperations#install",
      "impact": "A local principal who can write the build directory used by a root `setup.rb install` obtains root-equivalent control of the machine: root creates arbitrary directories, writes attacker-controlled file contents to any absolute path (for example replacing a `*.rb` file that later root processes `require`), and — via the chmod-before-unlink in `rm_f` following a symlink — sets mode 0777 on any existing root-owned file such as `/etc/shadow` or `/etc/sudoers`, which yields a direct root shell without needing control of the installed content at all.",
      "exploitScenarios": [
        "An operator builds the package out-of-tree or in a shared/world-writable build directory, running `ruby /trusted/src/setup.rb config` and `setup` there as an unprivileged user, then finishes with `sudo ruby /trusted/src/setup.rb install` as documented at setup.rb:788.",
        "Before the privileged step, the attacker edits (or races to create) `.config` in that build directory, adding the line `rb-dir=/tmp/attacker`; `ConfigTable#initialize_from_file` accepts it at setup.rb:285 because the key allow-list is only applied on the `[]=` path at setup.rb:297-299.",
        "The attacker creates `/tmp/attacker` and places a symlink inside it whose name matches an installed script, e.g. `ln -s /etc/shadow /tmp/attacker/sqlite3.rb`.",
        "Root runs the install task; `install_dir_lib` (setup.rb:1146) resolves the destination to `/tmp/attacker`, `mkdir_p` (setup.rb:1161, setup.rb:392) accepts it, and `install` computes `realdest = /tmp/attacker/sqlite3.rb` at setup.rb:443-444.",
        "`diff?` reports a difference, so setup.rb:448 calls `rm_f`, and setup.rb:401 executes `File.chmod 0777` through the symlink, leaving `/etc/shadow` world-writable while only the link is unlinked at setup.rb:402.",
        "The attacker rewrites root's password hash in the now world-writable `/etc/shadow` and logs in as root; alternatively the attacker skips the symlink, plants `lib/sqlite3.rb` with malicious code in the build directory (picked up via setup.rb:1198 and preferred via setup.rb:1209) and points `rb-dir` at a root Ruby load path so the next root process that requires the library executes attacker code."
      ],
      "preconditions": [
        "`setup.rb install` is executed with elevated privileges, which is the documented procedure (setup.rb:788, README.rdoc:19-21).",
        "The `.config` file in the working directory of that privileged run is writable by a principal less privileged than the installing user — either the standard `sudo ruby setup.rb install` in a build tree owned by an unprivileged user, or an out-of-tree/shared build directory while the source tree itself stays trusted (the srcdir/objdir split at setup.rb:628 vs setup.rb:672 makes this configuration supported).",
        "For the chmod-through-symlink variant, the attacker needs a directory they own to host the symlink and must know or guess an installed file's basename (`sqlite3.rb` here, derivable from the public repository layout).",
        "For the malicious-content variant, the attacker must be able to create a `*.rb` file in the build directory's `lib` subtree, which `existfiles` (setup.rb:1198) unions into the install list.",
        "`--no-harm` is not passed (default, setup.rb:768), and `setup.rb` is still used as an install path, which README.rdoc:19-21 documents."
      ],
      "recommendations": [
        "Root-cause fix: validate configuration on ingest rather than only on assignment — have `ConfigTable#initialize_from_file` (setup.rb:279-287) reject keys that fail `ConfigTable.config_key?` and re-validate `path_config?` values (require absolute, non-symlinked, prefix-contained paths), and refuse to consume a `.config` whose file ownership or containing-directory permissions are weaker than the effective user of the run.",
        "Hardening: make the privileged file operations link-safe and non-widening — replace the path-based `File.exist?`/`File.chmod 0777`/`File.unlink` sequence in `rm_f` (setup.rb:396-404) with an `lstat`-checked unlink that never chmods the victim, and in `install` (setup.rb:439-463) create the destination with `File::CREAT|File::EXCL|File::NOFOLLOW` and the final mode instead of opening a possibly pre-existing path and chmod'ing afterwards.",
        "Hardening: stop treating the object directory as a source of installable content, or require an explicit opt-in, so `existfiles` (setup.rb:1198) and `mapdir` (setup.rb:1207-1215) cannot promote files planted in the build directory into a privileged install.",
        "Regression test: run the `install` task under a fake root with a `.config` containing an out-of-allow-list key and an `rb-dir` pointing at a directory holding a symlink to a sentinel file, and assert both that the unknown key is rejected and that the sentinel's mode and contents are unchanged after the run."
      ],
      "cweId": "CWE-15"
    }
  ]
}
```