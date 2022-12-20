use crate::rollup::Rollup;
use crate::Transaction;

use super::account::{AccountId, AccountInformation, AccountPublicKey, AccountSecretKey};
use super::signature::{schnorr, SignatureScheme};
use super::transaction::SignedTransaction;
use ark_crypto_primitives::crh::{
    injective_map::{PedersenCRHCompressor, TECompressor},
    pedersen, TwoToOneCRH, CRH,
};
use ark_crypto_primitives::merkle_tree::{self, MerkleTree, Path};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_serialize::*;
use ark_std::rand::Rng;
use std::collections::HashMap;
use thiserror::Error;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

/// Represents transaction amounts and account balances.
#[derive(
    Hash,
    Eq,
    PartialEq,
    Copy,
    Clone,
    PartialOrd,
    Ord,
    Debug,
    CanonicalSerialize,
    CanonicalDeserialize,
)]
pub struct Amount(pub u64);

impl Amount {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

/// The parameters that are used in transaction creation and validation.
#[derive(Clone)]
pub struct Parameters {
    pub sig_params: schnorr::Parameters<EdwardsProjective>,
    pub leaf_crh_params: <TwoToOneHash as CRH>::Parameters,
    pub two_to_one_crh_params: <TwoToOneHash as TwoToOneCRH>::Parameters,
}

impl Parameters {
    pub fn sample<R: Rng>(rng: &mut R) -> Self {
        let sig_params = schnorr::Schnorr::setup(rng).unwrap();
        let leaf_crh_params = <LeafHash as CRH>::setup(rng).unwrap();
        let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(rng).unwrap();
        Self {
            sig_params,
            leaf_crh_params,
            two_to_one_crh_params,
        }
    }

    pub fn unsecure_hardcoded_parameters() -> Self {
        let mut rng = ark_std::test_rng();
        Self::sample(&mut rng)
    }
}

pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 4;
}

pub type LeafHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 144;
    const NUM_WINDOWS: usize = 4;
}

#[derive(Clone)]
pub struct MerkleConfig;
impl merkle_tree::Config for MerkleConfig {
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

/// A Merkle tree containing account information.
pub type AccMerkleTree = MerkleTree<MerkleConfig>;
/// The root of the account Merkle tree.
pub type AccRoot = <TwoToOneHash as TwoToOneCRH>::Output;
/// A membership proof for a given account.
pub type AccPath = Path<MerkleConfig>;

#[derive(Clone)]
pub struct State {
    /// What is the next available account identifier?
    pub next_available_account: Option<AccountId>,
    /// A mapping from an account's identifier to its information (= balance and public key).
    pub id_to_account_info: HashMap<AccountId, AccountInformation>,
    /// A mapping from a public key to an account's identifier.
    pub pub_key_to_id: HashMap<schnorr::PublicKey<EdwardsProjective>, AccountId>,
    /// Parameters used for signature verification.
    pub parameters: Parameters,
    /// Acccount Merkle tree.
    pub merkle_tree: AccMerkleTree,
    /// Acccount Merkle tree root history, used to track which batch of transactions are applied.
    pub merkle_root_history: Vec<AccRoot>,
}

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Unexpected state fork")]
    Fork,
    #[error("Invalid state root: {0} expected, {1} found")]
    InvalidTip(AccRoot, AccRoot),
    #[error("Trying to apply invalid transaction: {0:?}")]
    InvalidTransaction(SignedTransaction),
    #[error("Account not found: {0}")]
    AccountNotFound(AccountPublicKey),
}

impl State {
    /// Create an empty ledger that supports `num_accounts` accounts.
    pub fn new(num_accounts: usize) -> Self {
        let parameters = Parameters::unsecure_hardcoded_parameters();
        Self::new_with_parameters(num_accounts, &parameters)
    }

    /// Create an empty ledger that supports `num_accounts` accounts.
    pub fn new_with_parameters(num_accounts: usize, parameters: &Parameters) -> Self {
        let height = ark_std::log2(num_accounts);
        let account_merkle_tree = MerkleTree::blank(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            height as usize,
        )
        .unwrap();
        let pub_key_to_id = HashMap::with_capacity(num_accounts);
        let id_to_account_info = HashMap::with_capacity(num_accounts);
        let merkle_root: AccRoot = account_merkle_tree.root();
        Self {
            next_available_account: Some(AccountId(1)),
            id_to_account_info,
            pub_key_to_id,
            parameters: parameters.clone(),
            merkle_tree: account_merkle_tree,
            merkle_root_history: vec![merkle_root],
        }
    }

    /// Return the root of the account Merkle tree.
    pub fn current_merkle_tree(&self) -> &AccMerkleTree {
        &self.merkle_tree
    }

    /// Return the root of the account Merkle tree.
    pub(crate) fn current_merkle_tree_mut(&mut self) -> &mut AccMerkleTree {
        &mut self.merkle_tree
    }

    /// Return the root of the account Merkle tree.
    pub fn current_root(&self) -> AccRoot {
        self.current_merkle_tree().root()
    }

    /// Create a new account with public key `pub_key`. Returns a fresh account identifier
    /// if there is space for a new account, and returns `None` otherwise.
    /// The initial balance of the new account is 0.
    pub fn register(&mut self, public_key: AccountPublicKey) -> Option<AccountId> {
        self.next_available_account.and_then(|id| {
            // Construct account information for the new account.
            let account_info = AccountInformation {
                id,
                public_key,
                balance: Amount(0),
            };
            // Insert information into the relevant accounts.
            self.pub_key_to_id.insert(public_key, id);
            self.current_merkle_tree_mut()
                .update(id.0 as usize, &account_info.to_bytes_le())
                .expect("should exist");
            self.id_to_account_info.insert(id, account_info);
            // Increment the next account identifier.
            self.next_available_account
                .as_mut()
                .and_then(|cur| cur.checked_increment())?;
            Some(id)
        })
    }

    /// Samples keys and registers these in the ledger.
    pub fn sample_keys_and_register<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Option<(AccountId, AccountPublicKey, AccountSecretKey)> {
        let (pub_key, secret_key) =
            schnorr::Schnorr::keygen(&self.parameters.sig_params, rng).unwrap();
        self.register(pub_key).map(|id| (id, pub_key, secret_key))
    }

    /// Update the balance of `id` to `new_amount`.
    /// Returns `Some(())` if an account with identifier `id` exists already, and `None`
    /// otherwise.
    pub(crate) fn update_balance_by_id(
        &mut self,
        id: &AccountId,
        new_amount: Amount,
    ) -> Option<()> {
        let id_to_account_info = &mut self.id_to_account_info;
        let account_info = id_to_account_info.get_mut(id)?;
        account_info.balance = new_amount;
        let id = account_info.id.0 as usize;
        let bytes = account_info.to_bytes_le();
        self.current_merkle_tree_mut()
            .update(id, &bytes)
            .expect("Account must exist");
        Some(())
    }

    /// Update the balance of `id` to `new_amount`.
    /// Returns `Some(())` if an account with identifier `id` exists already, and `None`
    /// otherwise.
    pub(crate) fn update_balance_by_pk(
        &mut self,
        pk: &AccountPublicKey,
        new_amount: Amount,
    ) -> Option<()> {
        self.get_account_information_from_pk(pk)
            .and_then(|acc| self.update_balance_by_id(&acc.id, new_amount))
    }

    /// Update the state by applying the transaction `tx`, assuming `tx` is valid.
    pub(crate) fn unsafe_apply_transaction(&mut self, tx: &SignedTransaction) {
        let old_sender_bal = self
            .get_account_information_from_pk(&tx.sender())
            .expect("Must have checked validity of the transaction")
            .balance;
        let old_receiver_bal = self
            .get_account_information_from_pk(&tx.recipient())
            .expect("Must have checked validity of the transaction")
            .balance;
        let new_sender_bal = old_sender_bal
            .checked_sub(tx.amount())
            .expect("Must have checked validity of the transaction");
        let new_receiver_bal = old_receiver_bal
            .checked_add(tx.amount())
            .expect("Must have checked validity of the transaction");
        self.update_balance_by_pk(&tx.sender(), new_sender_bal);
        self.update_balance_by_pk(&tx.recipient(), new_receiver_bal);
    }

    /// Update the state by applying the transaction `tx`, if `tx` is valid.
    pub fn apply_transaction(&mut self, tx: &SignedTransaction) -> bool {
        if tx.validate(self) {
            self.unsafe_apply_transaction(tx);
            true
        } else {
            false
        }
    }

    pub fn get_account_information_from_id(&self, id: &AccountId) -> Option<AccountInformation> {
        self.id_to_account_info.get(id).copied()
    }

    pub fn get_account_information_from_pk(
        &self,
        pk: &AccountPublicKey,
    ) -> Option<AccountInformation> {
        self.pub_key_to_id
            .get(pk)
            .and_then(|id| self.get_account_information_from_id(id))
    }

    pub fn validate_transactions(&self, transactions: &[SignedTransaction]) -> bool {
        for tx in transactions {
            if !tx.validate(&*self) {
                return false;
            }
        }
        true
    }

    pub fn catchup_transactions(
        &mut self,
        transactions: &[Transaction],
        old_root: AccRoot,
        new_root: AccRoot,
    ) -> Result<(), StateError> {
        if self.current_root() != old_root {
            return Err(StateError::InvalidTip(old_root, self.current_root()));
        }
        let transactions: Vec<SignedTransaction> = transactions.iter().map(Into::into).collect();
        let (mut temp_state, _) = self.rollup_transactions(&transactions, false)?;
        let calculated_root = temp_state.current_root();
        if calculated_root != new_root {
            return Err(StateError::InvalidTip(calculated_root, new_root));
        }
        temp_state.merkle_root_history.push(new_root);
        *self = temp_state;
        Ok(())
    }

    pub fn rollup_transactions(
        &self,
        transactions: &[SignedTransaction],
        create_non_existent_accounts: bool,
    ) -> Result<(Self, Rollup), StateError> {
        self.do_rollup_transactions(transactions, create_non_existent_accounts, true)
    }

    pub(crate) fn do_rollup_transactions(
        &self,
        transactions: &[SignedTransaction],
        _create_non_existent_accounts: bool,
        validate_transactions: bool, // When set, only generating a not working rollup, useful for testing.
    ) -> Result<(Self, Rollup), StateError> {
        let mut temp_state = self.clone();
        let num_tx = transactions.len();
        let initial_root = Some(temp_state.current_root());
        let ledger_params = temp_state.parameters.clone();
        let mut sender_pre_tx_info_and_paths = Vec::with_capacity(num_tx);
        let mut recipient_pre_tx_info_and_paths = Vec::with_capacity(num_tx);
        let mut sender_post_paths = Vec::with_capacity(num_tx);
        let mut recipient_post_paths = Vec::with_capacity(num_tx);
        let mut post_tx_roots = Vec::with_capacity(num_tx);
        for tx in transactions {
            let sender_id = tx.sender();
            let recipient_id = tx.recipient();
            let sender_pre_acc_info = temp_state
                .get_account_information_from_pk(&sender_id)
                .ok_or(StateError::AccountNotFound(sender_id))?;
            let sender_pre_path = temp_state
                .current_merkle_tree()
                .generate_proof(sender_pre_acc_info.id.0 as usize)
                .expect("Already validated transaction above");
            let recipient_pre_acc_info = temp_state
                .get_account_information_from_pk(&recipient_id)
                .ok_or(StateError::AccountNotFound(recipient_id))?;
            let recipient_pre_path = temp_state
                .current_merkle_tree_mut()
                .generate_proof(recipient_pre_acc_info.id.0 as usize)
                .expect("Already validated transaction above");

            if validate_transactions && !temp_state.apply_transaction(tx) {
                return Err(StateError::InvalidTransaction(tx.clone()));
            }

            let post_tx_root = temp_state.current_root();
            let sender_post_path = temp_state
                .current_merkle_tree()
                .generate_proof(sender_pre_acc_info.id.0 as usize)
                .expect("Already validated transaction above");
            let recipient_post_path = temp_state
                .current_merkle_tree()
                .generate_proof(recipient_pre_acc_info.id.0 as usize)
                .expect("Already validated transaction above");
            sender_pre_tx_info_and_paths.push((sender_pre_acc_info, sender_pre_path));
            recipient_pre_tx_info_and_paths.push((recipient_pre_acc_info, recipient_pre_path));
            sender_post_paths.push(sender_post_path);
            recipient_post_paths.push(recipient_post_path);
            post_tx_roots.push(post_tx_root);
        }

        let final_root = temp_state.current_root();
        let rollup = Rollup {
            ledger_params,
            initial_root,
            final_root: Some(final_root),
            transactions: Some(transactions.iter().map(Into::into).collect()),
            signatures: Some(transactions.iter().map(|s| s.signature.clone()).collect()),
            sender_pre_tx_info_and_paths: Some(sender_pre_tx_info_and_paths),
            recv_pre_tx_info_and_paths: Some(recipient_pre_tx_info_and_paths),
            sender_post_paths: Some(sender_post_paths),
            recv_post_paths: Some(recipient_post_paths),
            post_tx_roots: Some(post_tx_roots),
        };
        temp_state.merkle_root_history.push(final_root);
        Ok((temp_state, rollup))
    }

    pub fn rollup_transactions_mut(
        &mut self,
        transactions: &[SignedTransaction],
        create_non_existent_accounts: bool,
    ) -> Result<Rollup, StateError> {
        let (temp_state, rollup) =
            self.rollup_transactions(transactions, create_non_existent_accounts)?;
        *self = temp_state;
        Ok(rollup)
    }
}

#[cfg(test)]
mod test {
    use super::SignedTransaction;
    use super::{Amount, Parameters, State};

    #[test]
    fn end_to_end() {
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new_with_parameters(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, alice_pk, alice_sk) = state.sample_keys_and_register(&mut rng).unwrap();
        // Let's give her some initial balance to start with.
        state
            .update_balance_by_id(&alice_id, Amount(10))
            .expect("Alice's account should exist");
        // Let's make an account for Bob.
        let (_bob_id, bob_pk, bob_sk) = state.sample_keys_and_register(&mut rng).unwrap();

        // Alice wants to transfer 5 units to Bob.
        let tx1 = SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(5), &alice_sk, &mut rng);
        assert!(tx1.validate(&state));
        assert!(state.apply_transaction(&tx1));
        // Let's try creating invalid transactions:
        // First, let's try a transaction where the amount is larger than Alice's balance.
        let bad_tx =
            SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(6), &alice_sk, &mut rng);
        assert!(!bad_tx.validate(&state));
        assert!(!state.apply_transaction(&bad_tx));
        // Next, let's try a transaction where the signature is incorrect:
        let bad_tx = SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(5), &bob_sk, &mut rng);
        assert!(!bad_tx.validate(&state));
        assert!(!state.apply_transaction(&bad_tx));

        // Finally, let's try a transaction to an non-existant account:
        let bad_tx = SignedTransaction::create(
            &pp,
            alice_pk,
            crate::account::non_existent_account(),
            Amount(5),
            &alice_sk,
            &mut rng,
        );
        assert!(!bad_tx.validate(&state));
        assert!(!state.apply_transaction(&bad_tx));
    }
}
