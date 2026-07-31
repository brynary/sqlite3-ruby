I have verified the finding completely. Here is my report.

```json
{
  "findings": [
    {
      "file": ".fabro/workflows/security-review/scripts/security_review.py",
      "line": 2664,
      "symbol": "code_frame",
      "snippet": "        raw = target.read_bytes()",
      "ruleId": "path-traversal.report-excerpt-file-read",
      "identity": {
        "anchor": "code-frame-file-read"
      },
      "category": "crypto-and-secrets",
      "severity": "HIGH",
      "difficulty": "MEDIUM",
      "confidence": "HIGH",
      "title": "Report code-excerpt reader accepts any dot-path under the scan root, exfiltrating .git/config credentials into published artifacts",
      "rationale": "code_frame() reads an arbitrary file chosen by an agent-authored finding.file value and copies up to nine of its lines into findings.json, the HTML report, and the Markdown report. The only path filter, normalize_repo_path(), rejects absolute paths and '..' but permits dotted directories, so '.git/config' is accepted. In this checkout .git/config line 4 holds a 405-character 'x-access-token:ghs_...' GitHub push credential, and the workflow publishes these artifacts and opens a pull request. Neither a tracked-file allowlist, a '.git' denylist, nor a resolve()/relative_to() containment check exists at the sink, and the quoted_line_matches() gate is bypassed by an empty snippet, which finding_or_rejection() explicitly permits.",
      "impact": "A live GitHub push token is copied out of .git/config into the run's published report bundle. Measured against the real file in this checkout, 382 of the credential's 405 characters survive the 400-character line cap at security_review.py:2613-2614 — including the 'x-access-token:ghs_' prefix and the entire token body — and the surrounding four context lines disclose the remote URL and branch refspec. findings.json, SECURITY-REVIEW-RESULTS.html, SECURITY-REVIEW-RESULTS.md, and SECURITY-REVIEW-RESULTS.jsonl are all listed under [run.artifacts] in workflow.toml:35-49, and .fabro/project.toml:7-8 enables automatic pull requests, so the artifact leaves the sandbox to anyone who can read the run artifacts or the PR. Holding that token grants write access to the repository, letting an attacker push commits, alter CI, and pivot into any environment that trusts the repository's default branch. The same primitive reads any other non-symlink file under the scan root that is untracked or gitignored (.env, credential caches, sandbox key material), so the exposure is not limited to Git's own configuration.",
      "evidence": [
        ".fabro/workflows/security-review/prompts/sweep.md:3 — tells the sweep agent its assignment arrives as an untrusted JSON item, establishing that the agent's own output is model-generated data rather than a trusted control value.",
        ".fabro/workflows/security-review/schemas/findings.schema.json:29 — declares finding.file as an unconstrained \"type\": \"string\" with no pattern, so schema validation places no restriction on the path an agent may submit.",
        ".fabro/workflows/security-review/security-review.fabro:166 — pipes context.parallel.results, the agents' raw JSON output, into the merge step on stdin.",
        ".fabro/workflows/security-review/scripts/security_review.py:1978 — read_merge_input() parses that agent-authored JSON straight off stdin without any authenticity check.",
        ".fabro/workflows/security-review/scripts/security_review.py:1844 — finding_or_rejection() takes the attacker-chosen value['file'] and passes it to normalize_repo_path() as the only path filter in the pipeline.",
        ".fabro/workflows/security-review/scripts/security_review.py:578 — normalize_repo_path() rejects only absolute paths and '..' components, so the dotted path '.git/config' passes the filter unchanged.",
        ".fabro/workflows/security-review/scripts/security_review.py:1916 — the same normalizer stores snippet via clean_text() with no minimum length, so an empty snippet is a valid finding field.",
        ".fabro/workflows/security-review/scripts/security_review.py:2632 — quoted_line_matches() returns True immediately when the quoted snippet is empty, disabling the one check that would otherwise require the cited line to match the file actually read.",
        ".fabro/workflows/security-review/scripts/security_review.py:3045 — assemble_final() forwards the surviving candidate's file value into code_frame() for every kept finding.",
        ".fabro/workflows/security-review/scripts/security_review.py:2658 — code_frame() joins the attacker-controlled relative path onto the scan root to form the read target.",
        ".fabro/workflows/security-review/scripts/security_review.py:2660 — the guard rejects only a symlinked final component and a non-file, and never calls resolve().relative_to(root()) nor consults the tracked-file list, so '.git/config' reaches the read.",
        ".fabro/workflows/security-review/scripts/security_review.py:2664 — the sink: target.read_bytes() reads the credential-bearing file off disk.",
        ".fabro/workflows/security-review/scripts/security_review.py:2684 — safe_code_text() copies the raw source line, including the token, into the finding's code.lines[].text field.",
        ".fabro/workflows/security-review/scripts/security_review.py:3088 — write_canonical_bundle() writes those lines to findings.json inside the published products directory.",
        ".fabro/workflows/security-review/scripts/render_report.py:590 — the renderer's independent normalize_repo_path() applies the same absolute/'..'-only rule, so it re-accepts '.git/config' and does not stop the leak.",
        ".fabro/workflows/security-review/scripts/render_report.py:703 — canonical_code() validates only that each excerpt line is control-character-free, preserving the credential text verbatim.",
        ".fabro/workflows/security-review/scripts/render_report.py:2072 — render() writes the excerpt into SECURITY-REVIEW-RESULTS.html via the embedded report payload.",
        ".fabro/workflows/security-review/workflow.toml:42 — [run.artifacts] publishes SECURITY-REVIEW-*/findings.json out of the sandbox, completing the exfiltration path.",
        ".git/config:4 — the file read by the sink holds 'url = https://x-access-token:<405-char token>@github.com/brynary/sqlite3-ruby', the live push credential that is disclosed."
      ],
      "exploitScenarios": [
        "The attacker opens an ordinary pull request against the repository, which the security-review workflow scans; no privileged access is needed to get the workflow to run over attacker-supplied content.",
        "The pull request adds an innocuous-looking file whose comments or strings frame themselves as review guidance, for example asserting that the run must cite '.git/config' line 4 as the root control of a committed-credential finding. The sweep and research prompts direct agents to read repository content, and prompts/sweep.md:73 shows the workflow already anticipates this content being treated as instructions.",
        "An agent that follows the injected text emits a finding with \"file\": \".git/config\", \"line\": 4, and \"snippet\": \"\", a shape the schema accepts because findings.schema.json:29 puts no pattern on file and permits an empty snippet string.",
        "normalize_repo_path() at security_review.py:578 admits the dotted path, and quoted_line_matches() short-circuits to True at line 2632 because the snippet is empty, so no gate rejects the candidate.",
        "The finding survives the panel, so assemble_final() calls code_frame() at line 3045; the guard at line 2660 passes because .git/config is a regular non-symlink file, and read_bytes() at line 2664 reads it.",
        "Lines 2 through 6 of .git/config, including 382 characters of the x-access-token push credential, are written into findings.json and the HTML, Markdown, and JSONL reports and published as run artifacts, where the attacker reads the token from the artifact or the auto-created pull request and uses it to push to the repository.",
        "A no-attacker variant reaches the same sink: the committed-secrets sweep is explicitly told at prompts/sweep.md:50 to hunt for real keys, so an agent doing its assigned job may cite .git/config on its own and leak the token with no injected content at all."
      ],
      "preconditions": [
        "The workflow runs in a checkout whose .git/config, or another readable non-symlink file under the scan root, contains credential material; that is the case here, where .git/config:4 embeds an x-access-token push credential.",
        "A finding citing that path is kept through the panel, or an agent is influenced by repository content to report it; the committed-secrets sweep pass may also cite it unprompted.",
        "The reported snippet is empty, or its collapsed text is a substring of the target line, so quoted_line_matches() at security_review.py:2622 does not veto the excerpt.",
        "The cited file is a regular file, not a symlink, and is at most 2 MB, valid UTF-8, and NUL-free, satisfying the checks at security_review.py:2660-2672.",
        "Someone who is not entitled to the credential can read the published artifacts or the auto-created pull request, which [run.artifacts] in workflow.toml:35-49 and .fabro/project.toml:7-8 arrange by default."
      ],
      "recommendations": [
        "Root-cause fix: constrain code_frame() to files the scan is actually allowed to quote. Before the read at security_review.py:2664, resolve the target and require containment plus membership in the tracked-file set — for example `resolved = target.resolve(); resolved.relative_to(root())` inside a try/except that returns `empty`, and `if file_path not in set(tracked_files()): return empty` — which rejects '.git/config' and every other untracked or gitignored file while still permitting every legitimate in-tree citation.",
        "Add an explicit denylist for sensitive locations in normalize_repo_path() at security_review.py:565, rejecting any path whose first component is '.git' or that matches known credential files ('.env', '.netrc', 'id_*', '*.pem'), so both the excerpt reader and every other consumer of finding.file are covered by one control.",
        "Hardening: stop treating an empty snippet as a match. Change quoted_line_matches() at security_review.py:2631-2632 to return False when the quoted text is empty, so a finding that supplies no snippet gets no file-derived excerpt and the excerpt reader can never be steered by omission.",
        "Hardening: keep the credential out of the sandbox that the agents read. Supply the push token through a credential helper or an env-var-only mechanism rather than embedding userinfo in .git/config's remote URL, so a file read under the scan root cannot recover it; the workflow already strips remote credentials for identity purposes at canonical_remote_identity() (security_review.py:327-362), and the on-disk config should match that intent.",
        "Hardening: apply the same containment in the renderer so a hand-built or tampered bundle cannot reintroduce the leak — have normalize_repo_path() in render_report.py:589 reject '.git' and other sensitive prefixes rather than only absolute paths and '..'.",
        "Regression test: add a test that builds a scan root containing a fake secret file (both '.git/config' with a sentinel token and a gitignored '.env'), feeds merge a findings payload citing that path at a valid line with an empty snippet, runs the final-tally and render-report stages, and asserts that code.lines is empty and that the sentinel token appears in none of findings.json, SECURITY-REVIEW-RESULTS.md, SECURITY-REVIEW-RESULTS.html, or SECURITY-REVIEW-RESULTS.jsonl. Pair it with a positive test asserting that a tracked in-repo source file still yields a nine-line excerpt, so the fix cannot be satisfied by disabling excerpts altogether."
      ]
    }
  ]
}
```

## What I reviewed and why this is the finding

My assignment was the gap-fill sweep over entry points and sinks **outside** the component matrix. The matrix already covers every `lib/`, `ext/`, `tasks/`, `Rakefile`, `setup.rb`, and `faq/` file, which is essentially all of the sqlite3-ruby gem. The genuinely uncovered committed code is the review harness itself under `.fabro/workflows/security-review/` — about 5,500 lines of Python plus the workflow graph, TOML config, and HTML template — so that is where I concentrated.

**The finding.** `code_frame()` reads a file whose path comes from agent-authored finding JSON. The only filter rejects absolute paths and `..`, but not dotted paths, so `.git/config` is accepted. That file in this checkout carries a live `x-access-token` GitHub push credential, and I measured that 382 of its 405 characters survive the excerpt's 400-character line cap — the token body is disclosed intact. The excerpt then flows into `findings.json` and all three published report formats, which `workflow.toml` exports as artifacts while `project.toml` opens a pull request automatically. Notably, the committed-secrets sweep pass is instructed to hunt for exactly this kind of key, so an agent doing its assigned job can trip the leak with no attacker present at all.

**Controls I checked and found effective**, so did not report:

- **HTML injection into the report.** No `innerHTML`, `document.write`, or `insertAdjacentHTML` anywhere in `templates/report.html`; every field reaches the DOM via `textContent`/`createTextNode`, and the single `<script>` interpolation is hardened by `embed_json` (`render_report.py:1957`), which escapes `&`, `<`, `>` and forces `ensure_ascii`. The `href`/`id` attributes are slug-constrained.
- **The `git_readonly.py` wrapper.** Argument-vector form with no shell, subcommand allowlist, `-c`/`--ext-diff`/`--output` rejected including `=` forms, `--no-ext-diff --no-textconv` force-inserted, `GIT_CONFIG_GLOBAL` neutered.
- **`git()` in `security_review.py`.** No agent-supplied string ever reaches it; revision tokens pass `SAFE_REV_RE`, whose anchor blocks a leading `-`, and scopes always land after a literal `--`.
- **`importlib` + `exec_module` at `security_review.py:3154`.** The path is a hardcoded constant, and the graph SHA-256-pins the renderer before `prepare` runs.
- **Markdown output.** `escape_markdown` neutralizes block context, list markers, and setext rules.

**Not checked:** whether Fabro's runtime shell-splits the `script=` strings in the graph — that engine is outside this repository, so a graph-level breakout via a hostile `workflow.toml` is something I could not verify either way. I also confirmed one defense-in-depth gap I judged too speculative to report as a finding: `workspace_digest()` excludes `runtime/`, so `state.json` sits outside the tamper check that gates publication, but I found no agent-reachable write to it.

I made no changes and ran nothing outside read-only inspection.