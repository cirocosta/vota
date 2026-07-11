# Vota Public Artifacts

All versioned protocol artifacts include `schema_version: 1` and
`protocol: "vota-v1-experimental"`. JSON shown here is descriptive; committed
fixtures under `testdata` are authoritative test inputs.

## Manifest

The manifest commits the draft ID, question, ordered choices, canonical
eligibility ring, trustee quorum and commitments, election public key, privacy
threshold, window, authority key, and experimental warning. `poll_id` and
`authority_signature` are derived last.

## Enrollment

Enrollment contains a draft poll identifier, one poll-specific eligibility key,
and a proof of possession. Real-world identity evidence is out of band and must
not be copied into public Vota artifacts.

## Ballot

The ballot contains one ciphertext per choice, a combined validity proof, the
ring link tag, the ring proof, and the ballot hash. It contains no ring override,
signer index, plaintext choice, or voter identity field.

## Receipt

The receipt identifies a ballot by hash and proves its accepted audit sequence.
It does not reveal the eligibility key or choice.

## Aggregate, shares, and tally

The aggregate contains summed ciphertexts only. Trustee shares bind to the exact
aggregate hash and include proof bytes plus a trustee Ed25519 signature. The tally
contains integer totals and the trustee IDs used to reach quorum.

## Audit record

An export contains the checkpoint public key, manifest, ordered events,
accepted canonical ballots, aggregate when closed, trustee shares, tally when
available, and checkpoint signatures. A fresh verifier requires no collector
database. Individual artifacts use a 1 MiB strict decoding limit. The complete
record container uses a 32 MiB limit because it can contain up to 256 ballots.
