# Threat model — nagual

A novel attack evades patterns — detection produces new antibodies with lineage. A forged vaccine poisons peers — adoption verifies issuer signatures and vaccine history before immunity is granted. An antibody is revoked silently — the immune log is hash-chained and exportable. A wildcard pattern over-matches — covers() semantics are testable and pattern specificity is recorded.

## What this crate guarantees

- Antibodies are signed and lineage-tracked; generation arithmetic is enforced.
- Vaccine adoption requires issuer signature + history verification.
- The immune log is hash-chained; immunity decisions are auditable offline.

## What it does not guarantee

- Protection against a verifier who never calls `verify()`.
- Integrity of inputs produced by other systems — this crate verifies
  signatures and chains over what it is given; garbage that verifies is
  still garbage.
