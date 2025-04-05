pub use snarkvm_console::{
    account::{Address, PrivateKey, Signature, ViewKey},
    network::{Environment, MainnetV0, TestnetV0},
    prelude::{FromBytes, FromFields, ToBytes, ToField, Uniform},
    program::{
        Ciphertext, Entry, EntryType, Identifier, Literal, Locator, Network, OutputID, Plaintext,
        PlaintextType, ProgramID, ProgramOwner, Record, RecordType, Response, StructType, Value,
        ValueType,
    },
    types::Field,
};

pub use snarkvm_circuit_network::{Aleo, AleoTestnetV0, AleoV0};

pub use snarkvm_ledger_store::{
    helpers::memory::{BlockMemory, ConsensusMemory},
    BlockStore, ConsensusStore,
};

pub use snarkvm_ledger_query::Query;

pub use snarkvm_synthesizer::{
    prelude::{
        cost_in_microcredits_v1, cost_in_microcredits_v2, deployment_cost, execution_cost_v1,
        execution_cost_v2,
    },
    snark::{Proof, ProvingKey, VerifyingKey},
    Process, Program, Trace, VM,
};

pub use snarkvm_ledger_block::{Block, Deployment, Execution, Transaction};
pub use snarkvm_utilities::bits::ToBits;
pub use snarkvm_algorithms::snark::varuna::VarunaVersion;

pub use indexmap::{IndexMap, IndexSet};

pub use snarkvm_fields::{PrimeField};

pub use aleo_rust::{AleoAPIClient, TransferType, Credits};

use serde::Serialize;

// Account types
pub type AddressNative = Address<CurrentNetwork>;
pub type PrivateKeyNative = PrivateKey<CurrentNetwork>;
pub type SignatureNative = Signature<CurrentNetwork>;
pub type ViewKeyNative = ViewKey<CurrentNetwork>;

// Network types
pub type CurrentNetwork = MainnetV0;
// pub type CurrentNetwork = TestnetV0;
pub type CurrentAleo = AleoV0;
// pub type CurrentAleo = AleoTestnetV0;

// Record types
pub type CiphertextNative = Ciphertext<CurrentNetwork>;
pub type PlaintextNative = Plaintext<CurrentNetwork>;
pub type PlaintextTypeNative = PlaintextType<CurrentNetwork>;
pub type RecordCiphertextNative = Record<CurrentNetwork, CiphertextNative>;
pub type RecordPlaintextNative = Record<CurrentNetwork, PlaintextNative>;
pub type RecordTypeNative = RecordType<CurrentNetwork>;

// Program types
type CurrentBlockMemory = BlockMemory<CurrentNetwork>;
pub type IdentifierNative = Identifier<CurrentNetwork>;
pub type ProcessNative = Process<CurrentNetwork>;
pub type ProgramIDNative = ProgramID<CurrentNetwork>;
pub type ProgramNative = Program<CurrentNetwork>;
pub type ProgramOwnerNative = ProgramOwner<CurrentNetwork>;
pub type ProvingKeyNative = ProvingKey<CurrentNetwork>;
pub type QueryNative = Query<CurrentNetwork, CurrentBlockMemory>;
pub type ResponseNative = Response<CurrentNetwork>;
pub type TransactionNative = Transaction<CurrentNetwork>;
pub type VerifyingKeyNative = VerifyingKey<CurrentNetwork>;
pub type ValueNative = Value<CurrentNetwork>;
pub type APIClient = AleoAPIClient<CurrentNetwork>;

pub type RecordData = IndexMap<Identifier<CurrentNetwork>, Entry<CurrentNetwork, PlaintextNative>>;

pub type EntryTypeNative = EntryType<CurrentNetwork>;

pub type StructTypeNative = StructType<CurrentNetwork>;
