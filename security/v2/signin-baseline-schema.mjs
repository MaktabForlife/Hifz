// A subject proof owns no full-stream cursor or snapshot state.
export const signInBaselineSchemaSQL = `
CREATE TABLE IF NOT EXISTS jwt_v2_signin_account_proofs (
 env TEXT NOT NULL, recipient TEXT NOT NULL, generation TEXT NOT NULL, owner_epoch TEXT NOT NULL,
 sub TEXT NOT NULL, ce INTEGER NOT NULL, ae INTEGER NOT NULL,
 coverage INTEGER NOT NULL, ordinal INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 proof_digest TEXT NOT NULL, proof TEXT NOT NULL,
 PRIMARY KEY(env,recipient,generation,owner_epoch,sub)
);
CREATE TABLE IF NOT EXISTS jwt_v2_signin_proof_receipts (
 operation_id TEXT PRIMARY KEY, proof_digest TEXT NOT NULL
);
`;
