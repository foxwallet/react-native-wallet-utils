use super::types::{
    APIClient, AddressNative, Ciphertext, Credits, CurrentAleo, CurrentNetwork, Environment,
    FromBytes, FromFields, IdentifierNative, PrimeField, PrivateKeyNative, ProcessNative,
    ProgramIDNative, ProgramManagerNative, ProgramNative, ProvingKeyNative, QueryNative,
    RecordCiphertextNative, RecordPlaintextNative, SignatureNative, ToBytes, ToField,
    TransactionNative, VerifyingKeyNative, ViewKeyNative,
    Entry,
    ValueNative,
    RecordTypeNative,
    EntryTypeNative,
    Network,
    PlaintextTypeNative,
    StructTypeNative,
    IndexMap,
    ToBits,
};
use super::utils::{
    convert_str_to_transfer_type, hex_to_bytes, serialize_account, serialize_aleo_error,
};
use crate::export;
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value, to_string};
use snarkvm_parameters::macros::set_dir;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::str::FromStr;
use std::time::Instant;
use crate::aleo::types::PlaintextNative;
use anyhow::{bail, ensure, Result};
use itertools::Itertools;

export! {
    @Java_com_foxwallet_core_WalletCoreModule_aleoDeserializeCreditsRecordInternal
    fn aleo_deserialize_credits_record(record_str: String) -> String {
        let record = RecordPlaintextNative::from_str(&record_str).map_err(|e| e.to_string());
        if let Err(error) = record {
          return serialize_aleo_error(&error);
        }
        let record = record.unwrap();
        let microcredits = record.microcredits().map_err(|e| e.to_string());
        if let Err(error) = microcredits {
          return serialize_aleo_error(&error);
        }
        let microcredits = microcredits.unwrap();

        println!("record: {} {} {}", record.owner(), microcredits, record.nonce());
        json!({
          "data": {
            "owner": **record.owner(),
            "microcredits": format!("{}", microcredits),
            "nonce": record.nonce(),
          },
          "error": "",
        }).to_string()
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoDecryptCiphertextInternal
    fn aleo_decrypt_ciphertext(ciphertext: String, view_key: String) -> String {
        let view_key = ViewKeyNative::from_str(&view_key).map_err(|e| e.to_string());
        if let Err(error) = view_key {
          return serialize_aleo_error(&error)
        }
        let view_key = view_key.unwrap();
        let field = view_key.to_field().map_err(|e| e.to_string());
        if let Err(error) = field {
          return serialize_aleo_error(&error)
        }
        let field = field.unwrap();
        println!("field: {}", field);
        let ciphertext = Ciphertext::<CurrentNetwork>::from_str(&ciphertext).map_err(|e| e.to_string());
        if let Err(error) = ciphertext {
          return serialize_aleo_error(&error)
        }
        let ciphertext = ciphertext.unwrap();
        println!("ciphertext: {}", ciphertext);
        let plaintext = ciphertext.decrypt_symmetric(field).map_err(|e| e.to_string());
        if let Err(error) = plaintext {
          return serialize_aleo_error(&error)
        }
        println!("plaintext {:?} ", plaintext);
        json!({
          "data": plaintext,
          "error": "",
        }).to_string()
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoDecryptRecordInternal
    fn aleo_decrypt_record(ciphertext: String, view_key: String) -> String {
        let view_key = ViewKeyNative::from_str(&view_key).map_err(|e| e.to_string());
        if let Err(error) = view_key {
          return serialize_aleo_error(&error);
        }
        let view_key = view_key.unwrap();
        let record = RecordCiphertextNative::from_str(&ciphertext).map_err(|e| e.to_string());
        if let Err(error) = record {
          return serialize_aleo_error(&error);
        }
        let record = record.unwrap();
        println!("record: {}", record);
        let decrypt_res = record.decrypt(&view_key).map_err(|_| "Decryption failed - view key did not match record".to_string());
        if let Err(error) = decrypt_res {
          return serialize_aleo_error(&error);
        }
        let decrypt_res = decrypt_res.unwrap();
        println!("plaintext {:?} ", decrypt_res);
        json!({
          "data": decrypt_res,
          "error": "",
        }).to_string()
    }

        @Java_com_foxwallet_core_WalletCoreModule_aleoGetRecordSerialNumberInternal
        fn aleo_get_record_serial_number(ciphertext: String, program_id: String, record_name: String, private_key: String) -> String {
            let private_key = PrivateKeyNative::from_str(&private_key).map_err(|e| e.to_string());
            if let Err(error) = private_key {
              return serialize_aleo_error(&error);
            }
            let private_key = private_key.unwrap();
            let view_key = ViewKeyNative::try_from(private_key).map_err(|e| e.to_string());
            if let Err(error) = view_key {
              return serialize_aleo_error(&error);
            }
            let view_key = view_key.unwrap();
            let record = RecordCiphertextNative::from_str(&ciphertext).map_err(|e| e.to_string());
            if let Err(error) = record {
              return serialize_aleo_error(&error);
            }
            let record = record.unwrap();
            println!("record: {}", record);
            let decrypt_res = record.decrypt(&view_key).map_err(|_| "Decryption failed - view key did not match record".to_string());
            if let Err(error) = decrypt_res {
              return serialize_aleo_error(&error);
            }
            let decrypt_res = decrypt_res.unwrap();
            let parsed_program_id =
                ProgramIDNative::from_str(&program_id).map_err(|_| "Invalid ProgramID specified".to_string());
            if let Err(error) = parsed_program_id {
              return serialize_aleo_error(&error);
            }
            let parsed_program_id = parsed_program_id.unwrap();
            let record_identifier = IdentifierNative::from_str(&record_name)
                .map_err(|_| "Invalid Identifier specified for record".to_string());
            if let Err(error) = record_identifier {
            return serialize_aleo_error(&error);
            }
            let record_identifier = record_identifier.unwrap();
            let commitment = decrypt_res
                .to_commitment(&parsed_program_id, &record_identifier)
                .map_err(|_| "A commitment for this record and program could not be computed".to_string());
            if let Err(error) = commitment {
            return serialize_aleo_error(&error);
            }
            let commitment = commitment.unwrap();
            let serial_number = RecordPlaintextNative::serial_number(private_key, commitment).map_err(|e| e.to_string());
            if let Err(error) = serial_number {
            return serialize_aleo_error(&error);
            }
            let serial_number = serial_number.unwrap();
            println!("serial_number {:?} ", serial_number);
            json!({
              "data": serial_number,
              "error": "",
            }).to_string()
        }


    @Java_com_foxwallet_core_WalletCoreModule_aleoSignMessageInternal
    fn aleo_sign_message(pk: String, message: String) -> String {
       let private_key = PrivateKeyNative::from_str(&pk).map_err(|e| e.to_string());
        if let Err(error) = private_key {
          return serialize_aleo_error(&error);
        }
        let private_key = private_key.unwrap();
        let msg_bytes = hex_to_bytes(&message).map_err(|e| e.to_string());
        if let Err(error) = msg_bytes {
          return serialize_aleo_error(&error);
        }
        let msg_bytes = msg_bytes.unwrap();
        let res = SignatureNative::sign_bytes(&private_key, &msg_bytes, &mut StdRng::from_entropy()).map_err(|e| e.to_string());
        if let Err(error) = res {
          return serialize_aleo_error(&error)
        }
        let res = res.unwrap();
        println!("res: {:?}", res);
        json!({
          "data": res.to_string(),
          "error": "",
        }).to_string()
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoGenerateProverFilesInternal
    fn aleo_generate_prover_files(dir: String, rpc_url: String, network: String, program_id: String, function_name: String, prover_file_path: String, verifier_file_path: String) -> String {
        set_dir(dir);
        let api_client = APIClient::new(&rpc_url, &network).map_err(|e| e.to_string());
        if let Err(error) = api_client {
          return serialize_aleo_error(&error);
        }
        let api_client = api_client.unwrap();
        let program_id = ProgramIDNative::from_str(&program_id).map_err(|e| e.to_string());
        if let Err(error) = program_id {
          return serialize_aleo_error(&error);
        }
        let program_id = program_id.unwrap();
        let program = api_client.get_program(program_id).map_err(|e| e.to_string());
        if let Err(error) = program {
          return serialize_aleo_error(&error);
        }
        let program = program.unwrap();
        let mut process = ProcessNative::load().map_err(|e| e.to_string());
        if let Err(error) = process {
          return serialize_aleo_error(&error);
        }
        let mut process = process.unwrap();
        let function_id = IdentifierNative::from_str(&function_name).map_err(|e| e.to_string());
        if let Err(error) = function_id {
          return serialize_aleo_error(&error);
        }
        let function_id = function_id.unwrap();
        let imports = api_client.get_program_imports_from_source(&program).map_err(|e| e.to_string());
        if let Err(error) = imports {
            return serialize_aleo_error(&error);
        }
        let imports = imports.unwrap();
        for (_, import) in imports.iter() {
            if import.id().to_string() != "credits.aleo" {
                let res = process.add_program(import).map_err(|e| e.to_string());
                if let Err(error) = res {
                    return serialize_aleo_error(&error);
                }
            }
        }
        if &program_id.to_string() != "credits.aleo" {
            let res = process.add_program(&program).map_err(|e| e.to_string());
            if let Err(error) = res {
              return serialize_aleo_error(&error);
            }
        }

        let res = process
            .synthesize_key::<CurrentAleo, _>(&program_id, &function_id, &mut StdRng::from_entropy())
            .map_err(|e| e.to_string());
        if let Err(error) = res {
          return serialize_aleo_error(&error);
        }
        let proving_key = process.get_proving_key(program_id, function_id).map_err(|e| e.to_string());
        if let Err(error) = proving_key {
          return serialize_aleo_error(&error);
        }
        let proving_key = proving_key.unwrap();
        let proving_key = ProvingKeyNative::from(proving_key);
        let prover_file= File::create(prover_file_path).map_err(|e| e.to_string());
        if let Err(error) = prover_file {
          return serialize_aleo_error(&error);
        }
        let prover_file = prover_file.unwrap();
        let mut writer = BufWriter::new(prover_file);
        let res = proving_key.write_le(&mut writer).map_err(|e| e.to_string());
        if let Err(error) = res {
          return serialize_aleo_error(&error);
        }
        let res = writer.flush().map_err(|e| e.to_string());
        if let Err(error) = res {
          return serialize_aleo_error(&error);
        }
        let verifying_key = process.get_verifying_key(program_id, function_id).map_err(|e| e.to_string());
        if let Err(error) = verifying_key {
          return serialize_aleo_error(&error);
        }
        let verifying_key = verifying_key.unwrap();
        let verifying_key = VerifyingKeyNative::from(verifying_key);
        let verifying_file= File::create(verifier_file_path).map_err(|e| e.to_string());
        if let Err(error) = verifying_file {
          return serialize_aleo_error(&error);
        }
        let verifying_file = verifying_file.unwrap();
        let mut writer = BufWriter::new(verifying_file);
        let res = verifying_key.write_le(&mut writer).map_err(|e| e.to_string());
        if let Err(error) = res {
          return serialize_aleo_error(&error);
        }
        let res = writer.flush().map_err(|e| e.to_string());
        if let Err(error) = res {
          return serialize_aleo_error(&error);
        }
        json!({
          "data": "success",
          "error": "",
        }).to_string()
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoExecuteProgramInternal
    fn aleo_execute_program(
        dir: String,
        rpc_url: String,
        network: String,
        pk: String,
        raw_program_id: String,
        function_name: String,
        // 序列化的数组
        inputs: String,
        fee_record_str: String,
        base_fee: String,
        priority_fee: String,
        prover_file_path: String,
        verifier_file_path: String,
        fee_prover_file_path: String,
        fee_verifier_file_path: String
    ) -> String {
        set_dir(dir);
        let client = APIClient::new(&rpc_url, &network).map_err(|e| e.to_string());
        if let Err(error) = client {
            return serialize_aleo_error(&error);
        }
        let client = client.unwrap();
        let private_key = PrivateKeyNative::from_str(&pk).map_err(|e| e.to_string());
        if let Err(error) = private_key {
            return serialize_aleo_error(&error);
        }
        let private_key = private_key.unwrap();
        // 初始化 process
        let mut process = ProcessNative::load().map_err(|e| e.to_string());
        if let Err(error) = process {
            return serialize_aleo_error(&error);
        }
        let mut process = process.unwrap();
        let program_id = ProgramIDNative::from_str(&raw_program_id).map_err(|e| e.to_string());
        if let Err(error) = program_id {
            return serialize_aleo_error(&error);
        }
        let program_id = program_id.unwrap();
        let program = client.get_program(program_id).map_err(|e| e.to_string());
        if let Err(error) = program {
            return serialize_aleo_error(&error);
        }
        let program = program.unwrap();
        let imports = client.get_program_imports_from_source(&program).map_err(|e| e.to_string());
        if let Err(error) = imports {
            return serialize_aleo_error(&error);
        }
        let imports = imports.unwrap();
        for (_, import) in imports.iter() {
            if import.id().to_string() != "credits.aleo" {
                let res = process.add_program(import).map_err(|e| e.to_string());
                if let Err(error) = res {
                    return serialize_aleo_error(&error);
                }
            }
        }
        // 准备参数
        // let inputs: Vec<String> = inputs.split('|').map(|x| x.to_string()).collect();
        let inputs: Result<Vec<String>, String> = serde_json::from_str(&inputs).map_err(|e| e.to_string());
        if let Err(error) = inputs {
            return serialize_aleo_error(&error);
        }
        let inputs = inputs.unwrap();
        println!("inputs: {:?}", inputs);
        let function_id = IdentifierNative::from_str(&function_name).map_err(|e| e.to_string());
        if let Err(error) = function_id {
            return serialize_aleo_error(&error);
        }
        let function_id = function_id.unwrap();

        // 初始化 key
        if raw_program_id != "credits.aleo" {
            let res = process.add_program(&program).map_err(|e| e.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }
        }
        let has_keys = process.get_stack(program_id).map_or_else(
            |_| false,
            |stack| stack.contains_proving_key(&function_id) && stack.contains_verifying_key(&function_id),
        );

        if has_keys {
            println!("Proving & verifying keys were specified for {} - {} but a key already exists in the cache. Using cached keys", program_id, function_id);
        } else {
            let prover_file = File::open(prover_file_path).map_err(|e| e.to_string());
            if let Err(error) = prover_file {
                return serialize_aleo_error(&error);
            }
            let prover_file = prover_file.unwrap();
            let prover_file_reader = BufReader::new(prover_file);
            let proving_key = ProvingKeyNative::read_le(prover_file_reader).map_err(|e| e.to_string());
            if let Err(error) = proving_key {
                return serialize_aleo_error(&error);
            }
            let proving_key = proving_key.unwrap();

            let verifier_file = File::open(verifier_file_path).map_err(|e| e.to_string());
            if let Err(error) = verifier_file {
                return serialize_aleo_error(&error);
            }
            let verifier_file = verifier_file.unwrap();
            let verifier_file_reader = BufReader::new(verifier_file);
            let verifying_key = VerifyingKeyNative::read_le(verifier_file_reader).map_err(|e| e.to_string());
            if let Err(error) = verifying_key {
                return serialize_aleo_error(&error);
            }
            let verifying_key = verifying_key.unwrap();

            let res = process
                .insert_proving_key(&program_id, &function_id, proving_key)
                .map_err(|e| e.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }

            let res = process
                .insert_verifying_key(&program_id, &function_id, verifying_key)
                .map_err(|e| e.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }
        }
        println!("start authorization");
        // 开始执行
        let authorization = process
        .authorize::<CurrentAleo, _>(
            &private_key,
            program_id,
            function_id,
            inputs.iter(),
            &mut StdRng::from_entropy(),
        )
        .map_err(|err| err.to_string());

        if let Err(error) = authorization {
            return serialize_aleo_error(&error);
        }
        let authorization = authorization.unwrap();
        let is_fee_required = !authorization.is_split();
        println!("start execute");

        let result = process
            .execute::<CurrentAleo, _>(authorization, &mut StdRng::from_entropy())
            .map_err(|err| err.to_string());
        if let Err(error) = result {
            return serialize_aleo_error(&error);
        }

        let (_, mut trace) = result.unwrap();
        let query = QueryNative::from(&rpc_url);
        let result = trace.prepare(query).map_err(|err| err.to_string());
        if let Err(error) = result {
            return serialize_aleo_error(&error);
        }
        let locator = format!("{}/{}", program.id().to_string(), function_name);
        println!("start prove_execution");

        let execution = trace
            .prove_execution::<CurrentAleo, _>(&locator, &mut StdRng::from_entropy())
            .map_err(|e| e.to_string());
        if let Err(error) = execution {
            return serialize_aleo_error(&error);
        }
        let execution = execution.unwrap();
        let execution_id = execution.to_execution_id().map_err(|e| e.to_string());
        if let Err(error) = execution_id {
            return serialize_aleo_error(&error);
        }
        let execution_id = execution_id.unwrap();
        println!("start fee require fee {} ", is_fee_required);

        if is_fee_required {
            let fee_func_id = if fee_record_str == "null" {
                IdentifierNative::from_str("fee_public").unwrap()
            } else {
                IdentifierNative::from_str("fee_private").unwrap()
            };
            let mut fee_record: Option<RecordPlaintextNative> = if fee_record_str != "null" {
                let fee_record_res = RecordPlaintextNative::from_str(&fee_record_str).map_err(|e| e.to_string());
                if let Err(error) = fee_record_res {
                    return serialize_aleo_error(&error);
                }
                Some(fee_record_res.unwrap())
            } else {
                None
            };

            let priority_fee: Result<u64, String> = priority_fee.parse().map_err(|_| "Invalid priority_fee".to_string());
            if let Err(error) = priority_fee {
                return serialize_aleo_error(&error);
            }
            let priority_fee = priority_fee.unwrap();

            let base_fee: Result<u64, String> = base_fee.parse().map_err(|_| "Invalid base_fee".to_string());
            if let Err(error) = base_fee {
                return serialize_aleo_error(&error);
            }
            let base_fee = base_fee.unwrap();
            let credits_id = ProgramIDNative::from_str("credits.aleo").map_err(|e| e.to_string());
            if let Err(error) = credits_id {
                return serialize_aleo_error(&error);
            }
            let credits_id = credits_id.unwrap();
            let has_keys = process.get_stack(credits_id).map_or_else(
                |_| false,
                |stack| stack.contains_proving_key(&fee_func_id) && stack.contains_verifying_key(&fee_func_id),
            );
            if has_keys {
                println!("Proving & verifying keys were specified for credits.aleo - fee but a key already exists in the cache. Using cached keys");
            } else {
                let fee_prover_file = File::open(fee_prover_file_path).map_err(|e| e.to_string());
                if let Err(error) = fee_prover_file {
                    return serialize_aleo_error(&error);
                }
                let fee_prover_file = fee_prover_file.unwrap();
                let fee_prover_file_reader = BufReader::new(fee_prover_file);
                let fee_proving_key = ProvingKeyNative::read_le(fee_prover_file_reader).map_err(|e| e.to_string());
                if let Err(error) = fee_proving_key {
                    return serialize_aleo_error(&error);
                }
                let fee_proving_key = fee_proving_key.unwrap();

                let fee_verifier_file = File::open(fee_verifier_file_path).map_err(|e| e.to_string());
                if let Err(error) = fee_verifier_file {
                    return serialize_aleo_error(&error);
                }
                let fee_verifier_file = fee_verifier_file.unwrap();
                let fee_verifier_file_reader = BufReader::new(fee_verifier_file);
                let fee_verifying_key = VerifyingKeyNative::read_le(fee_verifier_file_reader).map_err(|e| e.to_string());
                if let Err(error) = fee_verifying_key {
                    return serialize_aleo_error(&error);
                }
                let fee_verifying_key = fee_verifying_key.unwrap();

                let res = process
                    .insert_proving_key(&credits_id, &fee_func_id, fee_proving_key)
                    .map_err(|e| e.to_string());
                if let Err(error) = res {
                    return serialize_aleo_error(&error);
                }

                let res = process
                    .insert_verifying_key(&credits_id, &fee_func_id, fee_verifying_key)
                    .map_err(|e| e.to_string());
                if let Err(error) = res {
                    return serialize_aleo_error(&error);
                }
            }
            println!("start execute_fee");

            let fee_authorization = if fee_func_id.to_string() == "fee_public" {
                process.authorize_fee_public::<CurrentAleo, _>(&private_key, base_fee, priority_fee, execution_id, &mut StdRng::from_entropy()).map_err(|err| err.to_string())
            } else {
                process.authorize_fee_private::<CurrentAleo, _>(
                    &private_key,
                    fee_record.unwrap(),
                    base_fee,
                    priority_fee,
                    execution_id,
                    &mut StdRng::from_entropy(),
                ).map_err(|err| err.to_string())
            };
            if let Err(error) = fee_authorization {
                return serialize_aleo_error(&error);
            }
            let fee_authorization = fee_authorization.unwrap();
            let res = process.execute::<CurrentAleo, _>(fee_authorization, &mut StdRng::from_entropy()).map_err(|err| err.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }
            let (_, mut trace) = res.unwrap();
            let query = QueryNative::from(&rpc_url);
            let res = trace.prepare(query).map_err(|err| err.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }
            println!("start prove_fee");
            let final_fee = trace.prove_fee::<CurrentAleo, _>(&mut StdRng::from_entropy()).map_err(|e|e.to_string());
            if let Err(error) = final_fee {
                return serialize_aleo_error(&error);
            }
            let final_fee = final_fee.unwrap();
            println!("start verify_fee");
            let res = process.verify_fee(&final_fee, execution_id).map_err(|e| e.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }
            println!("start verify_execution");
            let res = process.verify_execution(&execution).map_err(|err| err.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }
            let transaction = TransactionNative::from_execution(execution, Some(final_fee)).map_err(|err| err.to_string());
            if let Err(error) = transaction {
                return serialize_aleo_error(&error);
            }
            let transaction = transaction.unwrap();
            println!("start transaction_broadcast");
            let res = client.transaction_broadcast(transaction.clone()).map_err(|err| err.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }
            json!({
                "data": transaction,
                "error": "",
            }).to_string()
        } else {
            println!("start verify_execution");
            let res = process.verify_execution(&execution).map_err(|err| err.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }
            let transaction = TransactionNative::from_execution(execution, None).map_err(|err| err.to_string());
            if let Err(error) = transaction {
                return serialize_aleo_error(&error);
            }
            let transaction = transaction.unwrap();
            println!("start transaction_broadcast");
            let res = client.transaction_broadcast(transaction.clone()).map_err(|err| err.to_string());
            if let Err(error) = res {
                return serialize_aleo_error(&error);
            }
            json!({
                "data": transaction,
                "error": "",
            }).to_string()
        }

    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoParseRecordInternal
    fn aleo_parse_record(plaintext: String) -> String {
        fn aleo_parse_entry(entry: &Entry<CurrentNetwork, PlaintextNative>) -> serde_json::Value {
            let (plaintext, visibility) = match entry {
                Entry::Constant(constant) => (constant, "constant"),
                Entry::Public(public) => (public, "public"),
                Entry::Private(private) => (private, "private"),
            };
            match plaintext {
                PlaintextNative::Literal(literal, ..) => {
                    serde_json::Value::String(format!("{}.{}", literal, visibility))
                }
                PlaintextNative::Struct(struct_, ..) => {
                    let mut map = serde_json::value::Map::new();
                    struct_.iter().enumerate().try_for_each(|(i, (name, plaintext))| {
                        match plaintext {
                            PlaintextNative::Literal(literal, ..) => {
                                map.insert(name.to_string(), serde_json::Value::String(format!("{}.{}", literal, visibility)));
                            },
                            PlaintextNative::Struct(..) | PlaintextNative::Array(..) => {
                                map.insert(name.to_string(), aleo_parse_entry(&match entry {
                                    Entry::Constant(..) => Entry::Constant(plaintext.clone()),
                                    Entry::Public(..) => Entry::Public(plaintext.clone()),
                                    Entry::Private(..) => Entry::Private(plaintext.clone()),
                                }));
                            }
                        }
                        Ok::<(), String>(())
                    });
                    Value::Object(map)
                }
                PlaintextNative::Array(array, ..) => {
                    // Print the opening bracket.
                    let mut res: Vec<serde_json::Value> = vec![];
                    // Print the members.
                    array.iter().enumerate().try_for_each(|(i, plaintext)| {
                        match plaintext {
                            PlaintextNative::Literal(literal, ..) => {
                                res.push(serde_json::Value::String(format!("{}.{}", literal, visibility)));
                            },
                            PlaintextNative::Struct(..) | PlaintextNative::Array(..) => {
                                res.push(aleo_parse_entry(&match entry {
                                    Entry::Constant(..) => Entry::Constant(plaintext.clone()),
                                    Entry::Public(..) => Entry::Public(plaintext.clone()),
                                    Entry::Private(..) => Entry::Private(plaintext.clone()),
                                }));
                            },
                        }
                        Ok::<(), String>(())
                    });
                    Value::Array(res)
                }
            }
        }

        let record = RecordPlaintextNative::from_str(&plaintext).map_err(|err| err.to_string());
        if let Err(error) = record {
            return serialize_aleo_error(&error);
        }
        let record = record.unwrap();
        let data = record.data();
        let mut map = serde_json::Map::new();
        for (key, value) in data {
            map.insert(key.to_string(), aleo_parse_entry(value));
        }
        json!({
          "data": map,
          "error": "",
        }).to_string()
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoGetProgramInfoInternal
    fn aleo_get_program_info(rpc_url: String, network: String, raw_program_id: String) -> String {
        let client = APIClient::new(&rpc_url, &network).map_err(|e| e.to_string());
        if let Err(error) = client {
          return serialize_aleo_error(&error);
        }
        let client = client.unwrap();
        let program_id = ProgramIDNative::from_str(&raw_program_id).map_err(|e| e.to_string());
        if let Err(error) = program_id {
          return serialize_aleo_error(&error);
        }
        let program_id = program_id.unwrap();
        let program = client.get_program(program_id).map_err(|e| e.to_string());
        if let Err(error) = program {
          return serialize_aleo_error(&error);
        }
        let program = program.unwrap();
        json!({
            "data": {
               "records": program.records(),
               "structs": program.structs(),
            },
            "error": "",
        }).to_string()
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoMatchRecordNameInternal
    fn aleo_match_record_name(plaintext: String, records_str: String, structs_str: String) -> String {
        fn matches_record_type(
            record: &RecordPlaintextNative,
            record_type: &RecordTypeNative,
            structs: &IndexMap<IdentifierNative, StructTypeNative>,
            depth: usize,
        ) -> Result<()> {
            // If the depth exceeds the maximum depth, then the plaintext type is invalid.
            ensure!(depth <= CurrentNetwork::MAX_DATA_DEPTH, "Plaintext exceeded maximum depth of {}", CurrentNetwork::MAX_DATA_DEPTH);

            // Retrieve the record name.
            let record_name = record_type.name();
            // Ensure the record name is valid.
            ensure!(!ProgramNative::is_reserved_keyword(record_name), "Record name '{record_name}' is reserved");

            // Ensure the visibility of the record owner matches the visibility in the record type.
            ensure!(
                record.owner().is_public() == record_type.owner().is_public(),
                "Visibility of record entry 'owner' does not match"
            );
            ensure!(
                record.owner().is_private() == record_type.owner().is_private(),
                "Visibility of record entry 'owner' does not match"
            );

            // Ensure the number of record entries does not exceed the maximum.
            let num_entries = record.data().len();
            ensure!(num_entries <= CurrentNetwork::MAX_DATA_ENTRIES, "'{record_name}' cannot exceed {} entries", CurrentNetwork::MAX_DATA_ENTRIES);

            // Ensure the number of record entries match.
            let expected_num_entries = record_type.entries().len();
            if expected_num_entries != num_entries {
                bail!("'{record_name}' expected {expected_num_entries} entries, found {num_entries} entries")
            }

            // Ensure the record data match, in the same order.
            for (i, ((expected_name, expected_type), (entry_name, entry))) in
                record_type.entries().iter().zip_eq(record.data().iter()).enumerate()
            {
                // Ensure the entry name matches.
                if expected_name != entry_name {
                    bail!("Entry '{i}' in '{record_name}' is incorrect: expected '{expected_name}', found '{entry_name}'")
                }
                // Ensure the entry name is valid.
                ensure!(!ProgramNative::is_reserved_keyword(entry_name), "Entry name '{entry_name}' is reserved");
                // Ensure the entry matches (recursive call).
                matches_entry_internal(record_name, entry_name, entry, expected_type, structs, depth + 1)?;
            }

            Ok(())
        }

        fn matches_entry_internal(
            record_name: &IdentifierNative,
            entry_name: &IdentifierNative,
            entry: &Entry<CurrentNetwork, PlaintextNative>,
            entry_type: &EntryTypeNative,
            structs: &IndexMap<IdentifierNative, StructTypeNative>,
            depth: usize,
        ) -> Result<()> {
            match (entry, entry_type) {
                (Entry::Constant(plaintext), EntryTypeNative::Constant(plaintext_type))
                | (Entry::Public(plaintext), EntryTypeNative::Public(plaintext_type))
                | (Entry::Private(plaintext), EntryTypeNative::Private(plaintext_type)) => {
                    match matches_plaintext_internal(plaintext, plaintext_type, structs, depth) {
                        Ok(()) => Ok(()),
                        Err(error) => bail!("Invalid record entry '{record_name}.{entry_name}': {error}"),
                    }
                }
                _ => bail!(
                    "Type mismatch in record entry '{record_name}.{entry_name}':\n'{entry}'\n does not match\n'{entry_type}'"
                ),
            }
        }

        fn matches_plaintext_internal(
            plaintext: &PlaintextNative,
            plaintext_type: &PlaintextTypeNative,
            structs: &IndexMap<IdentifierNative, StructTypeNative>,
            depth: usize,
        ) -> Result<()> {
            // If the depth exceeds the maximum depth, then the plaintext type is invalid.
            ensure!(depth <= CurrentNetwork::MAX_DATA_DEPTH, "Plaintext exceeded maximum depth of {}", CurrentNetwork::MAX_DATA_DEPTH);

            // Ensure the plaintext matches the plaintext definition in the program.
            match plaintext_type {
                PlaintextTypeNative::Literal(literal_type) => match plaintext {
                    // If `plaintext` is a literal, it must match the literal type.
                    PlaintextNative::Literal(literal, ..) => {
                        // Ensure the literal type matches.
                        match literal.to_type() == *literal_type {
                            true => Ok(()),
                            false => bail!("'{plaintext_type}' is invalid: expected {literal_type}, found {literal}"),
                        }
                    }
                    // If `plaintext` is a struct, this is a mismatch.
                    PlaintextNative::Struct(..) => bail!("'{plaintext_type}' is invalid: expected literal, found struct"),
                    // If `plaintext` is an array, this is a mismatch.
                    PlaintextNative::Array(..) => bail!("'{plaintext_type}' is invalid: expected literal, found array"),
                },
                PlaintextTypeNative::Struct(struct_name) => {
                    // Ensure the struct name is valid.
                    ensure!(!ProgramNative::is_reserved_keyword(struct_name), "Struct '{struct_name}' is reserved");

                    // Retrieve the struct from the program.
                    let Some(struct_) = structs.get(struct_name) else {
                        bail!("Struct '{struct_name}' is not defined in the program")
                    };

                    // Ensure the struct name matches.
                    if struct_.name() != struct_name {
                        bail!("Expected struct '{struct_name}', found struct '{}'", struct_.name())
                    }

                    // Retrieve the struct members.
                    let members = match plaintext {
                        PlaintextNative::Literal(..) => bail!("'{struct_name}' is invalid: expected struct, found literal"),
                        PlaintextNative::Struct(members, ..) => members,
                        PlaintextNative::Array(..) => bail!("'{struct_name}' is invalid: expected struct, found array"),
                    };

                    // Ensure the number of struct members does not exceed the maximum.
                    let num_members = members.len();
                    ensure!(
                        num_members <= CurrentNetwork::MAX_STRUCT_ENTRIES,
                        "'{struct_name}' cannot exceed {} entries",
                        CurrentNetwork::MAX_STRUCT_ENTRIES
                    );

                    // Ensure the number of struct members match.
                    let expected_num_members = struct_.members().len();
                    if expected_num_members != num_members {
                        bail!("'{struct_name}' expected {expected_num_members} members, found {num_members} members")
                    }

                    // Ensure the struct members match, in the same order.
                    for (i, ((expected_name, expected_type), (member_name, member))) in
                        struct_.members().iter().zip_eq(members.iter()).enumerate()
                    {
                        // Ensure the member name matches.
                        if expected_name != member_name {
                            bail!(
                                "Member '{i}' in '{struct_name}' is incorrect: expected '{expected_name}', found '{member_name}'"
                            )
                        }
                        // Ensure the member name is valid.
                        ensure!(!ProgramNative::is_reserved_keyword(member_name), "Member name '{member_name}' is reserved");
                        // Ensure the member plaintext matches (recursive call).
                        matches_plaintext_internal(member, expected_type, structs, depth + 1)?;
                    }

                    Ok(())
                }
                PlaintextTypeNative::Array(array_type) => match plaintext {
                    // If `plaintext` is a literal, this is a mismatch.
                    PlaintextNative::Literal(..) => bail!("'{plaintext_type}' is invalid: expected array, found literal"),
                    // If `plaintext` is a struct, this is a mismatch.
                    PlaintextNative::Struct(..) => bail!("'{plaintext_type}' is invalid: expected array, found struct"),
                    // If `plaintext` is an array, it must match the array type.
                    PlaintextNative::Array(array, ..) => {
                        // Ensure the array length matches.
                        let (actual_length, expected_length) = (array.len(), array_type.length());
                        if **expected_length as usize != actual_length {
                            bail!(
                                "'{plaintext_type}' is invalid: expected {expected_length} elements, found {actual_length} elements"
                            )
                        }
                        // Ensure the array elements match.
                        for element in array.iter() {
                            matches_plaintext_internal(element, array_type.next_element_type(), structs, depth + 1)?;
                        }
                        Ok(())
                    }
                },
            }
        }


        let record = RecordPlaintextNative::from_str(&plaintext).map_err(|err| err.to_string());
        if let Err(error) = record {
          return serialize_aleo_error(&error);
        }
        let record = record.unwrap();

        let structs_json: Result<Value, String> = serde_json::from_str(&structs_str).map_err(|err| err.to_string());
        if let Err(error) = structs_json {
          return serialize_aleo_error(&error);
        }
        let structs_json = structs_json.unwrap();
        let mut structs: IndexMap<IdentifierNative, StructTypeNative> = IndexMap::new();
        if let Value::Object(obj) = structs_json {
            for (key, value) in obj {
                let key = key.as_str();
                let id = IdentifierNative::from_str(&key).map_err(|err| err.to_string());
                if let Err(error) = id {
                    return serialize_aleo_error(&error);
                }
                let id = id.unwrap();
                let value = value.as_str().unwrap();
                let struct_type = StructTypeNative::from_str(&value).map_err(|err| err.to_string());
                if let Err(error) = struct_type {
                    return serialize_aleo_error(&error);
                }
                let struct_type = struct_type.unwrap();
                structs.insert(id, struct_type);
            }
        }
        let records_json: Result<Value, String> = serde_json::from_str(&records_str).map_err(|err| err.to_string());
        if let Err(error) = records_json {
          return serialize_aleo_error(&error);
        }
        let records_json = records_json.unwrap();
        if let Value::Object(obj) = records_json {
            for (key, value) in obj {
                let value = value.as_str().unwrap();
                let record_type = RecordTypeNative::from_str(&value).map_err(|err| err.to_string());
                if let Err(error) = record_type {
                    return serialize_aleo_error(&error);
                }
                let record_type = record_type.unwrap();
                let res = matches_record_type(&record, &record_type, &structs, 0);
                if let Err(error) = res {
                    continue;
                }
                return json!({
                    "data": key.to_string(),
                    "error": "",
                }).to_string();
            }
        }
        json!({
          "data": "",
          "error": "Not match",
        }).to_string()
    }



    @Java_com_foxwallet_core_WalletCoreModule_aleoGetRecordNameInternal
    fn aleo_get_record_name(raw_program: String, plaintext: String) -> String {
        fn matches_record_type(
            record: &RecordPlaintextNative,
            record_type: &RecordTypeNative,
            structs: &IndexMap<IdentifierNative, StructTypeNative>,
            depth: usize,
        ) -> Result<()> {
            // If the depth exceeds the maximum depth, then the plaintext type is invalid.
            ensure!(depth <= CurrentNetwork::MAX_DATA_DEPTH, "Plaintext exceeded maximum depth of {}", CurrentNetwork::MAX_DATA_DEPTH);

            // Retrieve the record name.
            let record_name = record_type.name();
            // Ensure the record name is valid.
            ensure!(!ProgramNative::is_reserved_keyword(record_name), "Record name '{record_name}' is reserved");

            // Ensure the visibility of the record owner matches the visibility in the record type.
            ensure!(
                record.owner().is_public() == record_type.owner().is_public(),
                "Visibility of record entry 'owner' does not match"
            );
            ensure!(
                record.owner().is_private() == record_type.owner().is_private(),
                "Visibility of record entry 'owner' does not match"
            );

            // Ensure the number of record entries does not exceed the maximum.
            let num_entries = record.data().len();
            ensure!(num_entries <= CurrentNetwork::MAX_DATA_ENTRIES, "'{record_name}' cannot exceed {} entries", CurrentNetwork::MAX_DATA_ENTRIES);

            // Ensure the number of record entries match.
            let expected_num_entries = record_type.entries().len();
            if expected_num_entries != num_entries {
                bail!("'{record_name}' expected {expected_num_entries} entries, found {num_entries} entries")
            }

            // Ensure the record data match, in the same order.
            for (i, ((expected_name, expected_type), (entry_name, entry))) in
                record_type.entries().iter().zip_eq(record.data().iter()).enumerate()
            {
                // Ensure the entry name matches.
                if expected_name != entry_name {
                    bail!("Entry '{i}' in '{record_name}' is incorrect: expected '{expected_name}', found '{entry_name}'")
                }
                // Ensure the entry name is valid.
                ensure!(!ProgramNative::is_reserved_keyword(entry_name), "Entry name '{entry_name}' is reserved");
                // Ensure the entry matches (recursive call).
                matches_entry_internal(record_name, entry_name, entry, expected_type, structs, depth + 1)?;
            }

            Ok(())
        }

        fn matches_entry_internal(
            record_name: &IdentifierNative,
            entry_name: &IdentifierNative,
            entry: &Entry<CurrentNetwork, PlaintextNative>,
            entry_type: &EntryTypeNative,
            structs: &IndexMap<IdentifierNative, StructTypeNative>,
            depth: usize,
        ) -> Result<()> {
            match (entry, entry_type) {
                (Entry::Constant(plaintext), EntryTypeNative::Constant(plaintext_type))
                | (Entry::Public(plaintext), EntryTypeNative::Public(plaintext_type))
                | (Entry::Private(plaintext), EntryTypeNative::Private(plaintext_type)) => {
                    match matches_plaintext_internal(plaintext, plaintext_type, structs, depth) {
                        Ok(()) => Ok(()),
                        Err(error) => bail!("Invalid record entry '{record_name}.{entry_name}': {error}"),
                    }
                }
                _ => bail!(
                    "Type mismatch in record entry '{record_name}.{entry_name}':\n'{entry}'\n does not match\n'{entry_type}'"
                ),
            }
        }

        fn matches_plaintext_internal(
            plaintext: &PlaintextNative,
            plaintext_type: &PlaintextTypeNative,
            structs: &IndexMap<IdentifierNative, StructTypeNative>,
            depth: usize,
        ) -> Result<()> {
            // If the depth exceeds the maximum depth, then the plaintext type is invalid.
            ensure!(depth <= CurrentNetwork::MAX_DATA_DEPTH, "Plaintext exceeded maximum depth of {}", CurrentNetwork::MAX_DATA_DEPTH);

            // Ensure the plaintext matches the plaintext definition in the program.
            match plaintext_type {
                PlaintextTypeNative::Literal(literal_type) => match plaintext {
                    // If `plaintext` is a literal, it must match the literal type.
                    PlaintextNative::Literal(literal, ..) => {
                        // Ensure the literal type matches.
                        match literal.to_type() == *literal_type {
                            true => Ok(()),
                            false => bail!("'{plaintext_type}' is invalid: expected {literal_type}, found {literal}"),
                        }
                    }
                    // If `plaintext` is a struct, this is a mismatch.
                    PlaintextNative::Struct(..) => bail!("'{plaintext_type}' is invalid: expected literal, found struct"),
                    // If `plaintext` is an array, this is a mismatch.
                    PlaintextNative::Array(..) => bail!("'{plaintext_type}' is invalid: expected literal, found array"),
                },
                PlaintextTypeNative::Struct(struct_name) => {
                    // Ensure the struct name is valid.
                    ensure!(!ProgramNative::is_reserved_keyword(struct_name), "Struct '{struct_name}' is reserved");

                    // Retrieve the struct from the program.
                    let Some(struct_) = structs.get(struct_name) else {
                        bail!("Struct '{struct_name}' is not defined in the program")
                    };

                    // Ensure the struct name matches.
                    if struct_.name() != struct_name {
                        bail!("Expected struct '{struct_name}', found struct '{}'", struct_.name())
                    }

                    // Retrieve the struct members.
                    let members = match plaintext {
                        PlaintextNative::Literal(..) => bail!("'{struct_name}' is invalid: expected struct, found literal"),
                        PlaintextNative::Struct(members, ..) => members,
                        PlaintextNative::Array(..) => bail!("'{struct_name}' is invalid: expected struct, found array"),
                    };

                    // Ensure the number of struct members does not exceed the maximum.
                    let num_members = members.len();
                    ensure!(
                        num_members <= CurrentNetwork::MAX_STRUCT_ENTRIES,
                        "'{struct_name}' cannot exceed {} entries",
                        CurrentNetwork::MAX_STRUCT_ENTRIES
                    );

                    // Ensure the number of struct members match.
                    let expected_num_members = struct_.members().len();
                    if expected_num_members != num_members {
                        bail!("'{struct_name}' expected {expected_num_members} members, found {num_members} members")
                    }

                    // Ensure the struct members match, in the same order.
                    for (i, ((expected_name, expected_type), (member_name, member))) in
                        struct_.members().iter().zip_eq(members.iter()).enumerate()
                    {
                        // Ensure the member name matches.
                        if expected_name != member_name {
                            bail!(
                                "Member '{i}' in '{struct_name}' is incorrect: expected '{expected_name}', found '{member_name}'"
                            )
                        }
                        // Ensure the member name is valid.
                        ensure!(!ProgramNative::is_reserved_keyword(member_name), "Member name '{member_name}' is reserved");
                        // Ensure the member plaintext matches (recursive call).
                        matches_plaintext_internal(member, expected_type, structs, depth + 1)?;
                    }

                    Ok(())
                }
                PlaintextTypeNative::Array(array_type) => match plaintext {
                    // If `plaintext` is a literal, this is a mismatch.
                    PlaintextNative::Literal(..) => bail!("'{plaintext_type}' is invalid: expected array, found literal"),
                    // If `plaintext` is a struct, this is a mismatch.
                    PlaintextNative::Struct(..) => bail!("'{plaintext_type}' is invalid: expected array, found struct"),
                    // If `plaintext` is an array, it must match the array type.
                    PlaintextNative::Array(array, ..) => {
                        // Ensure the array length matches.
                        let (actual_length, expected_length) = (array.len(), array_type.length());
                        if **expected_length as usize != actual_length {
                            bail!(
                                "'{plaintext_type}' is invalid: expected {expected_length} elements, found {actual_length} elements"
                            )
                        }
                        // Ensure the array elements match.
                        for element in array.iter() {
                            matches_plaintext_internal(element, array_type.next_element_type(), structs, depth + 1)?;
                        }
                        Ok(())
                    }
                },
            }
        }


        let record = RecordPlaintextNative::from_str(&plaintext).map_err(|err| err.to_string());
        if let Err(error) = record {
          return serialize_aleo_error(&error);
        }
        let record = record.unwrap();
        let program = ProgramNative::from_str(&raw_program).map_err(|err| err.to_string());
        if let Err(error) = program {
          return serialize_aleo_error(&error);
        }
        let program = program.unwrap();
        let records = program.records();
        let structs = program.structs();
        for (key,value) in records.iter() {
            let res = matches_record_type(&record, &value, structs, 0);
            if let Err(error) = res {
                continue;
            }
            return json!({
                "data": key.to_string(),
                "error": "",
            }).to_string();
        }
        json!({
          "data": "null",
          "error": "Not match",
        }).to_string()
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoHashBhp256Internal
    fn aleo_hash_bhp256(str_id: String) -> String {
        let value = ValueNative::from_str(&str_id).map_err(|err| err.to_string());
        if let Err(error) = value {
            return serialize_aleo_error(&error);
        }
        let value = value.unwrap();
        let id = CurrentNetwork::hash_bhp256(&value.to_bits_le()).map_err(|err| err.to_string());
        if let Err(error) = id {
            return serialize_aleo_error(&error);
        }
        let id = id.unwrap();
        id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_aleo_public_to_private_transfer_record() {
        let dir = String::from("./src/aleo_params/");
        let private_key =
            String::from("");
        let program_id = String::from("credits.aleo");
        let function_name = String::from("transfer_public_to_private");
        let inputs = serde_json::to_string(&["aleo1xs53pjftr8vst9ev2drwdu0kyyj2f4fxx93j3n30hfr8dqjnwq8qyvka7t", "2000000u64"]).unwrap();
        println!("raw inputs: {}", inputs);
        let fee_record = String::from("null");
        let base_fee = String::from("370000");
        let priority_fee = String::from("50000");
        let prover_file = format!("./src/aleo_params/{}-{}.prover", program_id, function_name);
        let verifier_file = format!(
            "./src/aleo_params/{}-{}.verifier",
            program_id, function_name
        );
        let fee_public_prover_file = format!("./src/aleo_params/fee_public.prover");
        let fee_public_verifier_file = format!("./src/aleo_params/fee_public.verifier");
        let fee_private_prover_file = format!("./src/aleo_params/fee_private.prover");
        let fee_private_verifier_file = format!("./src/aleo_params/fee_private.verifier");
        let start = Instant::now();
        let res = aleo_execute_program(
            dir,
            String::from("https://dev.foxnb.net/mobile/v1/aleo"),
            String::from("mainnet"),
            private_key,
            program_id,
            function_name,
            inputs,
            fee_record,
            base_fee,
            priority_fee,
            prover_file,
            verifier_file,
            fee_public_prover_file,
            fee_public_verifier_file,
        );
        let elapsed = start.elapsed();
        println!("Millis: {} ms", elapsed.as_millis());
        println!("result {:?} ", res);
        assert!(res.contains(r#"error":"""#));
    }

    #[test]
    fn test_aleo_split_record() {
        let dir = String::from("./src/aleo_params/");
        let private_key =
            String::from("");
        let program_id = String::from("credits.aleo");
        let function_name = String::from("split");
        let inputs = serde_json::to_string(&["{\n  owner: aleo1xs53pjftr8vst9ev2drwdu0kyyj2f4fxx93j3n30hfr8dqjnwq8qyvka7t.private,\n  microcredits: 2000000u64.private,\n  _nonce: 7364275430246742738179315920381733924740595470275114530575757694630527552686group.public\n}", "1000000u64"]).unwrap();
        println!("raw inputs: {}", inputs);
        let fee_record = String::from("null");
        let base_fee = String::from("null");
        let priority_fee = String::from("null");
        let prover_file = format!("./src/aleo_params/{}-{}.prover", program_id, function_name);
        let verifier_file = format!(
            "./src/aleo_params/{}-{}.verifier",
            program_id, function_name
        );
        let fee_public_prover_file = format!("null");
        let fee_public_verifier_file = format!("null");
        let fee_private_prover_file = format!("null");
        let fee_private_verifier_file = format!("null");
        let start = Instant::now();
        let res = aleo_execute_program(
            dir,
            String::from("https://dev.foxnb.net/mobile/v1/aleo"),
            String::from("mainnet"),
            private_key,
            program_id,
            function_name,
            inputs,
            fee_record,
            base_fee,
            priority_fee,
            prover_file,
            verifier_file,
            fee_public_prover_file,
            fee_public_verifier_file,
        );
        let elapsed = start.elapsed();
        println!("Millis: {} ms", elapsed.as_millis());
        println!("result {:?} ", res);
        assert!(res.contains(r#"error":"""#));
    }

    #[test]
    fn test_aleo_deserialize_record() {
        let input_record = String::from("{\n  owner: aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px.private,\n  microcredits: 93750000000000u64.private,\n  _nonce: 5338815352075887584819922423961148349629448203870952613119637127908069682550group.public\n}");
        let res = aleo_deserialize_credits_record(input_record);
        println!("{}", res);
        assert_eq!(
            res,
            r#"{"data":{"owner":"aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px","microcredits":"93750000000000","nonce":"5338815352075887584819922423961148349629448203870952613119637127908069682550group"},"error":""}"#
        );
    }

    #[test]
    fn test_aleo_decrypt_ciphertext() {
        let ciphertext = String::from("ciphertext1qgqxn5j5egd59rk0nfvvcrupgkf8c67d4k3sxpxvkzqs8ewjg0a67rvejfyppqralf8lqkjhefpuaptguctfkyzah25q5xjve6vvl0s8qc5mnrkg");
        let view_key = String::from("AViewKey1ggsbye8ZgyGYrnes6RsEmTCEbFDhZrcDHk9VX5YB9WMe");
        let res = aleo_decrypt_ciphertext(ciphertext, view_key);
        println!("res {}", res);
        assert_eq!(res, r#"{"data":{"plaintext":"93750000000000"},"error":""}"#);
    }

    #[test]
    fn test_aleo_get_record_serial_number() {
        let ciphertext = String::from("record1qyqsq0mfs2pwgmnmyavxe7ddx9cwjs2exltyu760fdfxvmv7du7gj4c2qyxx66trwfhkxun9v35hguerqqpqzq89dlvysmlz6hmg28nqmpk92ld09vqlc2s0kdfj2y0ggzueafr5qehj8dp6803xrlza4jf3tvxla2v60022wj97p37epdn2hxpzr3ypqrms3yf");
        let private_key = String::from("");
        let program_id = String::from("credits.aleo");
        let function_name = String::from("credits");
        let res = aleo_get_record_serial_number(ciphertext, program_id, function_name, private_key);
        println!("res {}", res);
        assert_eq!(res, r#"{"data":{"plaintext":"93750000000000"},"error":""}"#);
    }

    #[test]
    fn test_aleo_decrypt_record() {
        let record_text = String::from("record1qyqspxcwv5u9drsqy2m4ygspxl532p6qv4yv4jnf4fjm4z9r3fzcuaq3qyxx66trwfhkxun9v35hguerqqpqzqq0prywux6dygcn68arl8sm8dq7aygzrewg78ssl8s8kdasa2t3p7hvetx08fwgyuegx3l3u9qmsu86vqjm6ms5sd8cgw34wd3appypqh77wyh");
        let view_key = String::from("AViewKey1cYH2yRXZnF8zA7BkvJEbb1jvbkjWwg6o62gL2Lkcu87y");
        let res = aleo_decrypt_record(record_text, view_key);
        println!("res {}", res);
        assert_eq!(res, r#"{"data":"{\n  owner: aleo1xs53pjftr8vst9ev2drwdu0kyyj2f4fxx93j3n30hfr8dqjnwq8qyvka7t.private,\n  microcredits: 8487913u64.private,\n  _nonce: 6107817010861444819617966419532330448725697096257316234258501716059239895777group.public\n}","error":""}"#);
    }

    #[test]
    fn test_aleo_sign_message() {
        let private_key =
            String::from("");
        let message = String::from("48656c6c6f2c20576f726c6421");
        let res = aleo_sign_message(private_key, message);
        println!("result {:?} ", res);
        assert!(res.contains(r#"error":"""#));
    }

    #[test]
    fn test_aleo_generate_prover_files() {
        let dir = String::from("./src/aleo_params/");
        let program_id = String::from("credits.aleo");
        let function_name = String::from("fee_public");
        let prover_file = format!("./src/aleo_params/{}-{}.prover", program_id, function_name);
        let verifier_file = format!(
            "./src/aleo_params/{}-{}.verifier",
            program_id, function_name
        );
        let res =
            aleo_generate_prover_files(dir, String::from("https://dev.foxnb.net/mobile/v1/aleo"), String::from("mainnet"), program_id, function_name, prover_file, verifier_file);
        println!("result {:?} ", res);
        assert!(res.contains(r#"error":"""#));
    }

    #[test]
    fn test_aleo_execute_program() {
        let dir = String::from("./src/aleo_params/");
        let private_key =
            String::from("");
        let program_id = String::from("credits.aleo");
        let function_name = String::from("transfer_public");
        let inputs = serde_json::to_string(&["aleo1xs53pjftr8vst9ev2drwdu0kyyj2f4fxx93j3n30hfr8dqjnwq8qyvka7t", "100000u64"]).unwrap();
        println!("raw inputs: {}", inputs);
        let fee_record = String::from("null");
        let base_fee = String::from("57000");
        let priority_fee = String::from("20000");
        let prover_file = format!("./src/aleo_params/{}-{}.prover", program_id, function_name);
        let verifier_file = format!(
            "./src/aleo_params/{}-{}.verifier",
            program_id, function_name
        );
        let fee_public_prover_file = format!("./src/aleo_params/credits.aleo-fee_public.prover");
        let fee_public_verifier_file = format!("./src/aleo_params/credits.aleo-fee_public.verifier");
        let fee_private_prover_file = format!("./src/aleo_params/credits.aleo-fee_private.prover");
        let fee_private_verifier_file = format!("./src/aleo_params/credits.aleo-fee_private.verifier");
        let start = Instant::now();
        let res = aleo_execute_program(
            dir,
            String::from("https://dev.foxnb.net/mobile/v1/aleo"),
            String::from("mainnet"),
            private_key,
            program_id,
            function_name,
            inputs,
            fee_record,
            base_fee,
            priority_fee,
            prover_file,
            verifier_file,
            fee_public_prover_file,
            fee_public_verifier_file,
        );
        let elapsed = start.elapsed();
        println!("Millis: {} ms", elapsed.as_millis());
        println!("result {:?} ", res);
        assert!(res.contains(r#"error":"""#));
    }

    #[test]
    fn test_aleo_parse_record() {
        let record_text = String::from("{\n  owner: aleo1xs53pjftr8vst9ev2drwdu0kyyj2f4fxx93j3n30hfr8dqjnwq8qyvka7t.private,\n  token: 1field.private,\n  amount: 1000000u128.private,\n  _nonce: 8330039551488987378611890241359478445256923358029060207444253989434222025046group.public\n}");
        let except = String::from(r#"{"data":{"token":"1field.private","amount":"10000000000u128.private"},"error":""}"#);
        let res = aleo_parse_record(record_text);
        println!("res {}", res);
        assert_eq!(except, res);

        // let record_text = String::from("{\n  owner: aleo1xs53pjftr8vst9ev2drwdu0kyyj2f4fxx93j3n30hfr8dqjnwq8qyvka7t.private,\n  token: 1field.private,\n  amount: 10000000000u128.private,\n  _nonce: 2101679574711592313386896873192856645190699089023911072544541006048163611328group.public\n}");
        let record_text = String::from(r"{
           owner: aleo1xs53pjftr8vst9ev2drwdu0kyyj2f4fxx93j3n30hfr8dqjnwq8qyvka7t.private,
           foo: 5u8.private,
           bar: {
                baz: 10field.private,
                qux: {
                    quux: {
                        corge: {
                            grault: {
                                garply: {
                                    waldo: {
                                        fred: {
                                            plugh: {
                                                xyzzy: {
                                                    thud: true.private
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
           },
           _nonce: 2101679574711592313386896873192856645190699089023911072544541006048163611328group.public
        }");
        let except = String::from(r#"{"data":{"foo":"5u8.private","bar":{"baz":"10field.private","qux":{"quux":{"corge":{"grault":{"garply":{"waldo":{"fred":{"plugh":{"xyzzy":{"thud":"true.private"}}}}}}}}}}},"error":""}"#);
        let res = aleo_parse_record(record_text);
        println!("res {}", res);
        assert_eq!(except, res);
    }

    #[test]
    fn test_aleo_match_record_name() {
        let plaintext = String::from("{\n  owner: aleo1xs53pjftr8vst9ev2drwdu0kyyj2f4fxx93j3n30hfr8dqjnwq8qyvka7t.private,\n  data: 7695298536662493485104165609951371166429709890207755337137712968763917912722field.private,\n  edition: 0scalar.private,\n  _nonce: 3795843049584774052156625883016045597575638745783487044747931476329774607232group.public\n}");
        let records = String::from(r#"{"NFT":"record NFT:\n    owner as address.private;\n    data as field.private;\n    edition as scalar.private;","NFT_ownership":"record NFT_ownership:\n    owner as address.private;\n    nft_owner as address.private;\n    data as field.private;\n    edition as scalar.private;"}"#);
        let structs = String::from(r#"{"BaseURI":"struct BaseURI:\n    data0 as u128;\n    data1 as u128;\n    data2 as u128;\n    data3 as u128;","ResolverIndex":"struct ResolverIndex:\n    name as field;\n    category as u128;\n    version as u64;","Name":"struct Name:\n    name as [u128; 4u32];\n    parent as field;","NameStruct":"struct NameStruct:\n    name as [u128; 4u32];\n    parent as field;\n    resolver as u128;"}"#);
        let res = aleo_match_record_name(plaintext, records, structs);
        let except = String::from(r#"{"data":"NFT","error":""}"#);
        assert_eq!(except, res);
    }

    #[test]
    fn test_aleo_get_program_info() {
        let rpc_url = String::from(" https://dev.foxnb.net/mobile/v1/aleo");
        let chain_id = String::from("mainnet");
        let program_id = String::from("aleo_name_service_registry_v1.aleo");


        let res = aleo_get_program_info(rpc_url, chain_id, program_id);
        println!("res {}", res);
        let except = String::from(r#"{"data":"NFT","error":""}"#);
        assert_eq!(except, res);
    }

    #[test]
    fn test_balance_id() {
        let address = String::from("aleo1xs53pjftr8vst9ev2drwdu0kyyj2f4fxx93j3n30hfr8dqjnwq8qyvka7t");
        let token_id = String::from("7256611128845787327915514673706878554991764894124833271035508826370970880865field");
        let str_id = format!("{{token: {}, user: {}}}", token_id, address);
        let id = aleo_hash_bhp256(str_id);
        println!("res {}", id);
        assert_eq!(id.to_string(), "1883796586130720708904835108018912833399065797923770589550083011607438845009field");
    }
}
