<!--
Two things this template asks for are not machine-checkable: whether a claim's label is honest, and
whether the change keeps this repository's index in step. The gate output is the cheapest evidence
you can give a reviewer; a green run is not approval, and a blank section is not an omission nobody
will notice.
-->

## What this changes

One or two sentences. Name the file or the behaviour, not the intention.

## What I ran

```bash
python check_repo.py && python check_refs.py && python check_routing.py \
  && python check_commands.py && python check_budget.py && python -m pytest -q
```

Paste the output that decides the question, including any gate that was red before the change and
why. Report only checks that actually executed — `should pass` is not a result, and a run on one
device, one ABI or one sample says so in the line where it is quoted.

```
<decisive output>
```

If `mypy` or `flake8` are not installed locally, say that here: CI runs them, and a contributor
without them cannot reproduce that half.

## Claims

Every claim carries one of the four labels this repository uses. `observed` requires both the command
and its output; `inferred` means it was not run; `unverified` means someone else said so; `unknown`
means nobody looked.

| Claim | Label | Command and result, or what would have to exist for it to be `observed` |
|---|---|---|
| | observed / inferred / unverified / unknown | |

- [ ] No chain is labelled above its weakest step.
- [ ] A negative result says whether it was `absent`, `unknown` or `present but unreadable`, and names
      the probe's coverage. Only the first is a finding.
- [ ] A measurement names the version, device or ABI it came from.

## What has to move with it

Check every line that applies. These are the rows that cost a red CI run when they are missed.

- [ ] A reference file — named in `references/routing.md`, reachable from `SKILL.md` or the README,
      with a load-this-when head if it passes 100 lines.
- [ ] A script — a row in the routing script table, its capability declared in
      `scripts/capabilities.py`, and `--help` working on a bare interpreter.
- [ ] A symptom-index row — mirrored into `references/routing.md`, which is compared rather than
      generated.
- [ ] A section heading — every section reference that pointed at the old name is updated.
- [ ] A documented command — the flags are copied from `--help`, not retyped.
- [ ] `SKILL.md` — the budget line is attached above; it is loaded in full on activation.
- [ ] A capability claim — the row in `evidence/capability-matrix.json` **and** the line in
      `references/evidence-summary.md`. No gate compares them; that is why the reviewer reads them.
- [ ] A new pitfall — next number, same four headings.
- [ ] `README.md` and `README.zh-CN.md` — the two stay in step.
- [ ] Documentation only — say so explicitly; a blank list is not the same statement.

## Boundaries

Where something could not be exercised here, ship the measured half plus an explicitly labelled
template for the rest, and state what would have to exist for the other half to become `observed`.

- [ ] Anything needing a device, adb, frida, a rooted phone or the network is named as not run here,
      rather than described as working.
- [ ] One variable changed per result: if a result moved, it is attributable to the one thing this
      change touched.
- [ ] The scan in `scripts/scan_leaks.py` was run over the files being published, and its findings
      are resolved — including names and metadata that no pattern reads.
