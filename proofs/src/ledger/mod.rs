use crate::account::sentinel_account;
use crate::rollup::Rollup;
use crate::serde::SerdeAsHex;
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
use derivative::Derivative;
use serde::{Deserialize, Serialize, Serializer};
use serde_with::serde_as;
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
    Serialize,
    Deserialize,
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

    pub fn safe_amount_for_sentinel_account() -> Self {
        Amount(u64::MAX / 2)
    }
}

/// The parameters that are used in transaction creation and validation.
#[derive(Clone, Debug, Default)]
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

#[derive(Derivative, Clone)]
#[derivative(Debug)]
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
    #[derivative(Debug = "ignore")]
    pub merkle_tree: AccMerkleTree,
    /// Acccount Merkle tree root history, used to track which batch of transactions are applied.
    pub merkle_root_history: Vec<AccRoot>,
    /// Number of accounts that is contained in Merkle tree.
    pub num_of_accounts: usize,
}

const DEFUALT_NUM_OF_ACCOUNTS: usize = 256;

impl Serialize for State {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WiredState::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for State {
    fn deserialize<D>(deserializer: D) -> Result<State, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ws = <WiredState as Deserialize>::deserialize(deserializer)?;
        TryFrom::try_from(&ws).map_err(serde::de::Error::custom)
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WiredState {
    #[serde_as(as = "SerdeAsHex")]
    pub merkle_tree_root: AccRoot,
    pub num_of_accounts: usize,
    pub accounts: Vec<AccountInformation>,
}

impl From<&State> for WiredState {
    fn from(state: &State) -> WiredState {
        let accounts = state.export_to_account_information();
        let num_of_accounts = state.num_of_accounts;
        let merkle_tree_root = state.current_root();
        WiredState {
            merkle_tree_root,
            num_of_accounts,
            accounts,
        }
    }
}

impl TryFrom<&WiredState> for State {
    type Error = StateError;
    fn try_from(ws: &WiredState) -> Result<State, Self::Error> {
        State::import_from_account_information(ws.num_of_accounts, &ws.accounts)
    }
}

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Unexpected state fork at {0}")]
    Fork(AccRoot),
    #[error("Invalid state root: {0} expected, {1} found")]
    InvalidTip(AccRoot, AccRoot),
    #[error("Trying to apply invalid transaction: {0:?}")]
    InvalidTransaction(SignedTransaction),
    #[error("Account not found: {0}")]
    AccountNotFound(AccountPublicKey),
    #[error("Account id {0:?} already existed")]
    Existed(AccountId),
}

impl State {
    /// Create an empty ledger that supports `num_accounts` accounts.
    pub fn new() -> Self {
        let parameters = Parameters::unsecure_hardcoded_parameters();
        Self::new_with_parameters(&parameters)
    }

    pub fn new_with_num_of_accounts(num_accounts: usize) -> Self {
        let parameters = Parameters::unsecure_hardcoded_parameters();
        Self::new_blank_state(num_accounts, &parameters)
    }

    /// Create an empty ledger that supports `num_accounts` accounts.
    pub fn new_blank_state(num_accounts: usize, parameters: &Parameters) -> Self {
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
            num_of_accounts: num_accounts,
        }
    }

    /// Create an empty ledger that supports `num_accounts` accounts.
    pub fn new_with_parameters(parameters: &Parameters) -> Self {
        let mut state = Self::new_blank_state(DEFUALT_NUM_OF_ACCOUNTS, parameters);

        state.register(sentinel_account());
        // TODO: fix this.
        // Dirty hack to make burning and minting assets works.
        // Otherwise, we need to check if the sender or recipient is the sentinel_account.
        // If so, don't add/sub amount from it. But I Found no way to short circuit r1cs circuits.
        // That is, r1cs circuits will always do checked_add/sub, thus proof
        // generation/verification fails.
        state
            .update_balance_by_pk(
                &sentinel_account(),
                Amount::safe_amount_for_sentinel_account(),
            )
            .expect("Sentinel account is created above");
        state
    }

    pub fn add_account_information(
        &mut self,
        account_info: AccountInformation,
    ) -> Result<(), StateError> {
        // TODO: check account limit here.
        let id = account_info.id;
        if self.id_to_account_info.contains_key(&id) {
            return Err(StateError::Existed(id));
        };

        self.id_to_account_info.insert(id, account_info);
        let next_id = self.next_available_account.expect("State initialized");
        if next_id <= id {
            self.next_available_account = Some(AccountId(id.0 + 1))
        }
        Ok(())
    }

    pub fn export_to_account_information(&self) -> Vec<AccountInformation> {
        self.id_to_account_info.iter().map(|(_k, v)| *v).collect()
    }

    pub fn import_from_account_information(
        num_accounts: usize,
        account_information: &[AccountInformation],
    ) -> Result<Self, StateError> {
        let parameters = Parameters::unsecure_hardcoded_parameters();
        let mut state = Self::new_blank_state(num_accounts, &parameters);
        for info in account_information {
            state.add_account_information(*info)?
        }
        Ok(state)
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
        let new_sender_bal = old_sender_bal
            .checked_sub(tx.amount())
            .expect("Must have checked validity of the transaction");
        self.update_balance_by_pk(&tx.sender(), new_sender_bal);
        let old_receiver_bal = self
            .get_account_information_from_pk(&tx.recipient())
            .expect("Must have checked validity of the transaction")
            .balance;
        let new_receiver_bal = old_receiver_bal
            .checked_add(tx.amount())
            .expect("Must have checked validity of the transaction");
        self.update_balance_by_pk(&tx.recipient(), new_receiver_bal);
    }

    /// Update the state by applying the transaction `tx`, if `tx` is valid.
    pub fn apply_transaction(&mut self, tx: &SignedTransaction, validate_signature: bool) -> bool {
        if tx.validate(self, validate_signature) {
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

    /// Commit current merkle tree root to merkle root history
    pub fn commit_current_merkle_root(&mut self) -> AccRoot {
        let last_root = self.merkle_root_history.last().expect("State initialized");
        let current_root = self.current_root();
        if *last_root != current_root {
            self.merkle_root_history.push(current_root);
        }
        current_root
    }

    pub fn catchup_transactions(
        &mut self,
        transactions: &[Transaction],
        old_root: AccRoot,
        new_root: AccRoot,
    ) -> Result<(), StateError> {
        // Check if transactions are already applied or there is an unexpected fork.
        for (prev, next) in self
            .merkle_root_history
            .iter()
            .zip(self.merkle_root_history.iter().skip(1))
        {
            if *prev == old_root {
                if *next != new_root {
                    return Err(StateError::Fork(old_root));
                } else {
                    return Ok(());
                }
            }
        }
        if self.current_root() != old_root {
            return Err(StateError::InvalidTip(old_root, self.current_root()));
        }
        let transactions: Vec<SignedTransaction> = transactions.iter().map(Into::into).collect();
        let (temp_state, _) = self.do_rollup_transactions(&transactions, false, true, false)?;
        let calculated_root = temp_state.current_root();
        if calculated_root != new_root {
            return Err(StateError::InvalidTip(calculated_root, new_root));
        }
        *self = temp_state;
        Ok(())
    }

    pub fn rollup_transactions(
        &self,
        transactions: &[SignedTransaction],
        create_non_existent_accounts: bool,
    ) -> Result<(Self, Rollup), StateError> {
        self.do_rollup_transactions(transactions, create_non_existent_accounts, true, true)
    }

    pub(crate) fn do_rollup_transactions(
        &self,
        transactions: &[SignedTransaction],
        _create_non_existent_accounts: bool,
        validate_transactions: bool, // When set, only generating a not working rollup, useful for testing.
        validate_signatures: bool,   // Disable signature verfication for verified transactions.
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
                .current_merkle_tree()
                .generate_proof(recipient_pre_acc_info.id.0 as usize)
                .expect("Already validated transaction above");

            if validate_transactions && !temp_state.apply_transaction(tx, validate_signatures) {
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

impl Default for State {
    fn default() -> Self {
        Self::new()
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
        let mut state = State::new_with_parameters(&pp);
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
        assert!(tx1.validate(&state, true));
        assert!(state.apply_transaction(&tx1, true));
        // Let's try creating invalid transactions:
        // First, let's try a transaction where the amount is larger than Alice's balance.
        let bad_tx =
            SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(6), &alice_sk, &mut rng);
        assert!(!bad_tx.validate(&state, true));
        assert!(!state.apply_transaction(&bad_tx, true));
        // Next, let's try a transaction where the signature is incorrect:
        let bad_tx = SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(5), &bob_sk, &mut rng);
        assert!(!bad_tx.validate(&state, true));
        assert!(!state.apply_transaction(&bad_tx, true));

        // Finally, let's try a transaction to an non-existant account:
        let bad_tx = SignedTransaction::create(
            &pp,
            alice_pk,
            crate::account::non_existent_account(),
            Amount(5),
            &alice_sk,
            &mut rng,
        );
        assert!(!bad_tx.validate(&state, true));
        assert!(!state.apply_transaction(&bad_tx, true));
    }

    #[test]
    fn catchup_transactions() {
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new_with_parameters(&pp);
        let (alice_id, alice_pk, alice_sk) = state.sample_keys_and_register(&mut rng).unwrap();
        state
            .update_balance_by_id(&alice_id, Amount(10))
            .expect("Alice's account should exist");
        let (_bob_id, bob_pk, bob_sk) = state.sample_keys_and_register(&mut rng).unwrap();

        // Apply transaction 1
        let old_root = state.commit_current_merkle_root();
        let tx1 = SignedTransaction::create(&pp, alice_pk, bob_pk, Amount(5), &alice_sk, &mut rng);
        assert!(state.rollup_transactions_mut(&[tx1.clone()], true).is_ok());

        // Reapply transaction 1
        let new_root = state.current_root();
        assert!(state
            .catchup_transactions(&[(&tx1).into()], old_root, new_root)
            .is_ok());

        // Apply transaction 2
        let tx2 = SignedTransaction::create(&pp, bob_pk, alice_pk, Amount(3), &bob_sk, &mut rng);
        assert!(state.rollup_transactions_mut(&[tx2.clone()], false).is_ok());

        // Apply transaction 1 with the wrong final root
        assert!(state
            .catchup_transactions(&[(&tx1).into()], new_root, old_root)
            .is_err());

        // Reapply transaction 2
        assert!(state
            .catchup_transactions(&[tx2.into()], new_root, state.current_root())
            .is_ok());

        // Reapply transaction 1
        assert!(state
            .catchup_transactions(&[(&tx1).into()], old_root, new_root)
            .is_ok());
    }
}
