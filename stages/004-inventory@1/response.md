{
  "components": [
    {
      "name": "c-extension",
      "paths": ["ext/sqlite3"],
      "language": "C",
      "role": "Native Ruby/C extension binding SQLite3: database open/close, SQL prepare/step, BLOB and value marshalling, authorizer/busy/progress callbacks into Ruby, plus extconf.rb build configuration",
      "internetFacing": false
    },
    {
      "name": "ruby-api",
      "paths": ["lib/sqlite3.rb", "lib/sqlite3"],
      "language": "Ruby",
      "role": "High-level Ruby API: database/statement wrappers, SQL quoting and construction, pragmas, type translation, result sets",
      "internetFacing": false
    },
    {
      "name": "install-script",
      "paths": ["setup.rb"],
      "language": "Ruby",
      "role": "Legacy standalone installer executed with user privileges at package install time (config/setup/install file operations)",
      "internetFacing": false
    },
    {
      "name": "build-tasks",
      "paths": ["Rakefile", "tasks"],
      "language": "Ruby",
      "role": "Rake build/release automation, including vendor_sqlite3.rake which downloads and extracts SQLite3 binaries over plain HTTP (supply-chain surface)",
      "internetFacing": false
    },
    {
      "name": "faq-generator",
      "paths": ["faq"],
      "language": "Ruby",
      "role": "Developer documentation tool parsing faq.yml via YAML and RedCloth to emit HTML",
      "internetFacing": false
    }
  ],
  "securityScanSkippedComponents": [
    {
      "name": "test-suite",
      "paths": ["test"],
      "reason": "Unit/integration test suite; not shipped with the gem and not executed in production"
    },
    {
      "name": "review-workflow-scaffolding",
      "paths": [".fabro"],
      "reason": "Agent security-review workflow configuration, prompts, schemas, and scripts; review tooling, not product code"
    },
    {
      "name": "review-run-output",
      "paths": ["SECURITY-REVIEW-20260731-180332"],
      "reason": "Generated state and report output of this review run"
    },
    {
      "name": "root-docs-and-metadata",
      "paths": ["README.rdoc", "CHANGELOG.rdoc", "API_CHANGES.rdoc", "ChangeLog.cvs", "LICENSE", "Manifest.txt", ".gitignore"],
      "reason": "Non-executable documentation and packaging metadata"
    },
    {
      "name": "vcs-internals",
      "paths": [".git"],
      "reason": "Git object store and refs; VCS internals, not product code"
    }
  ]
}