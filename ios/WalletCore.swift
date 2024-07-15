import Foundation

func handle_error<T, U>(
  resolve: RCTPromiseResolveBlock,
  reject: RCTPromiseRejectBlock,
  get_result: (UnsafeMutablePointer<ExternError>) -> T,
  success: (T) -> U
) -> Void {
  var err = ExternError()
  let err_ptr: UnsafeMutablePointer<ExternError> = UnsafeMutablePointer(&err)
  let res = get_result(err_ptr)
  if err_ptr.pointee.code == 0 {
    resolve(success(res))
  } else {
    let val = String(cString: err_ptr.pointee.message)
    core_destroy_string(err_ptr.pointee.message)
    reject(String(describing: err_ptr.pointee.code), val, nil)
  }
}

@objc(WalletCore)
class WalletCore: NSObject {

  public static func requiresMainQueueSetup() -> Bool {
    return true;
  }

  @objc func ironfishCreateAccount(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
    handle_error(
      resolve: resolve,
      reject: reject,
      get_result: { ironfish_create_account($0) },
      success: { (res: Optional<UnsafePointer<CChar>>) -> String in
        let val = String(cString: res!)
        core_destroy_string(res!)
        return val
    })
  }

  @objc func ironfishCreateAccountFromPrivateKey(_ pk: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
    handle_error(
      resolve: resolve,
      reject: reject,
      get_result: { ironfish_create_account_from_pk($0, pk) },
      success: { (res: Optional<UnsafePointer<CChar>>) -> String in
        let val = String(cString: res!)
        core_destroy_string(res!)
        return val
    })
  }

  @objc func ironfishSignTransaction(_ rawTx: String, pk: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { ironfish_sign_transaction($0, rawTx, pk) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func ironfishInitSaplingParams(_ mintParamsPath: String, spendParamsPath: String, outputParamsPath: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { ironfish_init_sapling_params($0, mintParamsPath, spendParamsPath, outputParamsPath) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func ironfishIsValidAddress(_ address: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { ironfish_is_valid_public_address($0, address) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoCreateAccountFromSeed(_ seed: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_create_account_from_seed($0, seed) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoCreateAccountFromPrivateKey(_ pk: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_create_account_from_pk($0, pk) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoIsValidAddress(_ address: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_is_valid_public_address($0, address) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoDeserializeCreditsRecord(_ recordStr: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_deserialize_credits_record($0, recordStr) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoSignMessage(_ pk: String, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_sign_message($0, pk, message) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoGenerateProverFiles(_ dir: String, rpc_url: String, network: String, program_id: String, function_name: String, prover_file_path: String, verifier_file_path: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_generate_prover_files($0, dir, rpc_url, network, program_id, function_name, prover_file_path, verifier_file_path) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoExecuteProgram(_ dir: String, rpc_url: String, network: String, pk: String, program_id: String, function_name: String, inputs: String, fee_record: String, base_fee: String, priority_fee: String, prover_file_path: String, verifier_file_path: String, fee_prover_file_path: String, fee_verifier_file_path: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_execute_program($0, dir, rpc_url, network, pk, program_id, function_name, inputs, fee_record, base_fee, priority_fee, prover_file_path, verifier_file_path, fee_prover_file_path, fee_verifier_file_path) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoDecryptRecord(_ ciphertext: String, vk: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_decrypt_record($0, ciphertext, vk) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoParseRecord(_ plaintext: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_parse_record($0, plaintext) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func aleoHashBhp256(_ str: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
   handle_error(
     resolve: resolve,
     reject: reject,
     get_result: { aleo_hash_bhp256($0, str) },
     success: { (res: Optional<UnsafePointer<CChar>>) -> String in
       let val = String(cString: res!)
       core_destroy_string(res!)
       return val
   })
  }

  @objc func spaceMeshAddressFromPubKey(_ pub: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    resolve(FoxSpaceMeshAddressFromPubKey(pub))
  }

  @objc func spaceMeshCreateTransaction(_ pk: String, to: String, amount: String, nonce: String, gasPrice: String, genesisID: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    resolve(FoxSpaceMeshCreateTransaction(pk, to, amount, nonce, gasPrice, genesisID))
  }

  @objc func spaceMeshSelfSpawnTx(_ pk: String, nonce: String, gasPrice: String, genesisID: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    resolve(FoxSpaceMeshSelfSpawnTx(pk, nonce, gasPrice, genesisID))
  }
}

