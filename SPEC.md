# SPEC — nagual (adaptive immune system)

## Registry

`ImmuneRegistry` is organism-scoped (its owner's pubkey) and keeps a
hash-chained `ImmuneEvent` log: detections, antibody developments,
vaccine exports/adoptions, revocations.

## Pathogen

`detect(me, signature, severity, evidence)` records an attack pattern.
Signatures are glob patterns — `ignore previous *` matches mid-string.

## Antibody

`develop(me, pathogen_id, pattern, parent?)` produces a signed antibody:

```json
{
  "id": "sha256", "issuer": "pubkey", "pathogen": "signature",
  "pattern": "counter-pattern", "generation": 1,
  "parent": "antibody id or null", "ts": 0, "signature": "…"
}
```

Generation = parent generation + 1; parent must exist in this registry.

## Vaccine

`export_vaccine(me, antibody_id)` packages `{ antibody,
pathogen_signature, lineage }` signed by the issuer. `adopt_vaccine`
verifies the signature and lineage before granting local immunity.

## Immunity

`is_immune(input)` ⇒ any adopted or locally-developed antibody whose
pattern covers the input. `covers()` supports leading, trailing, and
mid-pattern `*` wildcards.

## Invariants

- Antibodies cannot be forged — ed25519 over canonical body.
- Adoption requires verified lineage; a vaccine cannot invent ancestry.
- All decisions are replayable from the immune log, offline.
