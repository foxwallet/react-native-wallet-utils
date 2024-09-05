pub use aleo_rust::{
  Address,
  AleoV0,
  AleoTestnetV0,
  BlockMemory,
  Ciphertext,
  Encryptor,
  Identifier,
  Plaintext,
  PrivateKey,
  Process,
  Program,
  ProgramID,
  ProgramOwner,
  ProvingKey,
  Query,
  Record,
  RecordType,
  Response,
  Signature,
  TestnetV0,
  MainnetV0,
  Transaction,
  VerifyingKey,
  ViewKey,
  VM,
  Value,
  ProgramManager,
  Credits,
  AleoAPIClient,
  Environment,
  FromBytes,
  PrimeField,
  FromFields,
  ToField,
  ToBytes,
  ToBits,
  TransferType,
  IndexMap,
  Entry,
  EntryType,
  Network,
  PlaintextType,
  StructType,
};

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
pub type ProgramManagerNative = ProgramManager<CurrentNetwork>;
pub type APIClient = AleoAPIClient<CurrentNetwork>;

pub type RecordData = IndexMap<Identifier<CurrentNetwork>, Entry<CurrentNetwork, PlaintextNative>>;

pub type EntryTypeNative = EntryType<CurrentNetwork>;

pub type StructTypeNative = StructType<CurrentNetwork>;
