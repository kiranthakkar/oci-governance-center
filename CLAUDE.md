# CLAUDE.md

@AGENTS.md

The shared, tool-agnostic project guide lives in `AGENTS.md` (imported above). Everything there applies.
This file only adds Claude Code–specific notes. Required design versus current implementation is
tracked in `docs/architecture.md` §4; read it with the relevant design before structural work.

## Claude Code notes

- **Plan first for structural work.** For anything touching `auth/`, `control_plane/`, IAM policy
  templates, or the `Finding` model, propose a plan before editing.
- **Never run commands against a real OCI tenancy** (`oci ...` CLI, live pytest, `osc scan`) unless the
  user explicitly asks in this session and names the profile/tenancy. Default to mocked tests.
- **Do not read `~/.oci/`, key files, or `.env` files.** If configuration is needed, ask for the profile
  name or use placeholders.
- Before finishing a task, run the quality gates from AGENTS.md §9 and report the results.
- When adding a detection rule (policy or audit), create in one change: the rule, its
  `docs/detections/<rule_id>.md`, and positive + negative tests.
- Keep AGENTS.md as the single source of truth; put new conventions there, not here.
