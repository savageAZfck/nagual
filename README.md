# nagual

**An adaptive immune system for autonomous agents — attack signatures become signed, lineage-tracked antibodies shared as vaccines across the mesh.**

Named for the Nahuatl *nagual* — the guardian spirit that watches over a being.

## Why this exists

Static blocklists die the day they're written. A real immune system does three things a firewall can't: **detect** novel attack signatures (pathogens), **derive** countermeasures (antibodies), and **share** them so one organism's attack becomes everyone's immunity (vaccination).

## Model

- `Pathogen` — detected attack signature: evidence-hashed, severity-classed, first-seen provenance.
- `Antibody` — signed counter-signature with *lineage*: which pathogen it answers and which parent antibody it was refined from (generation 1, 2, 3…). Glob patterns (`*` anywhere) cover variants.
- `Vaccine` — an antibody packaged for export, envelope-signed so receivers verify both the countermeasure and its chain of custody.
- `ImmuneRegistry` — hash-chained history: detections, developments, adoptions. The organism can't hide how it got its immunity.

## Properties

- Idempotent detection — the same signature never double-chains.
- Forgery-proof — tampered vaccine patterns fail signature verification on adoption.
- Herd immunity — first attack a peer sees, every organism is immune to.
- Registry heads notarizable by `kola` witnesses.

## Try it

```bash
cargo run --example immune
cargo test
```

## Pair with

- `macuahuitl` — the static firewall nagual's antibodies feed.
- `axon` — reflexes that *assert* on what the immune system *learns*.
- `dreamcatcher` — vaccine shares ride the same signed mesh documents.
