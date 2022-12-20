# CellPool Hackathon

Folder structure

- `cellpool/`: CKB contract

## Contract

Use the contract as lock script.

- Setup: Generate key pair and use the verifying key as the script args.
- Create: Create the cell without an input with the same verifying key
    - The initial root hash is the empty tree
    - The final root hash is in the output cell
        - TODO: We omit the creation verification here
- Update: Use the cell locked by the verifying key as input and create an output cell with the same key.
    - The initial root hash is in the input cell
    - The final root hash is in the output cell
    - The input lock witness contains the proof and transactions hashes.

### Wire Format

- args: `VerifyingKey<Bls12_381>` serialized via `ark_serialize`
- witness: `CellPoolWitness` serialized via `ark_serialize`

```
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CellPoolWitness {
    pub proof: Proof<Bls12_381>,
    // Every transaction is the result of Transaction::to_bytes_le
    // See https://github.com/contrun/cellpool-proofs/blob/d870af409f8baa1f5eb7aa3ba2366ec41c411a43/src/transaction/mod.rs#L34
    pub transactions: Vec<Vec<u8>>,
}
```

### Test

```
capsule build
capsule test
```
