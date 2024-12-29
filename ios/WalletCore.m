#import <React/RCTBridgeModule.h>
#import <Foundation/Foundation.h>
#import <GoCore/GoCore.h>
#include "RustCore.h"

@interface RCT_EXTERN_MODULE(WalletCore, NSObject)

// explanation about threading here: https://stackoverflow.com/a/50775641/3060739
- (dispatch_queue_t)methodQueue
{
  return dispatch_get_main_queue();
}

+ (BOOL)requiresMainQueueSetup
{
  return YES;
}

RCT_EXTERN_METHOD(ironfishCreateAccount:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(ironfishCreateAccountFromPrivateKey:(NSString*)pk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(ironfishSignTransaction:(NSString*)rawTx pk:(NSString*)pk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(ironfishInitSaplingParams:(NSString*)mintParamsPath spendParamsPath:(NSString*)spendParamsPath outputParamsPath:(NSString*)outputParamsPath resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(ironfishIsValidAddress:(NSString*)address resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoCreateAccountFromSeed:(NSString*)seed resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoCreateAccountFromPrivateKey:(NSString*)pk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoIsValidAddress:(NSString*)address resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoDeserializeCreditsRecord:(NSString*)recordStr resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoSignMessage:(NSString*)pk message:(NSString*)message resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoGenerateProverFiles:(NSString*)dir rpc_url:(NSString*)rpc_url network:(NSString*)network program_id:(NSString*)program_id function_name:(NSString*)function_name prover_file_path:(NSString*)prover_file_path verifier_file_path:(NSString*)verifier_file_path resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoExecuteProgram:(NSString*)dir rpc_url:(NSString*)rpc_url network:(NSString*)network pk:(NSString*)pk program_id:(NSString*)program_id function_name:(NSString*)function_name inputs:(NSString*)inputs fee_record:(NSString*)fee_record base_fee:(NSString*)base_fee priority_fee:(NSString*)priority_fee prover_file_path:(NSString*)prover_file_path verifier_file_path:(NSString*)verifier_file_path fee_prover_file_path:(NSString*)fee_prover_file_path fee_verifier_file_path:(NSString*)fee_verifier_file_path resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoDecryptRecord:(NSString*)ciphertext vk:(NSString*)vk resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoParseRecord:(NSString*)plaintext resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(aleoHashBhp256:(NSString*)str resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(ironfishCreateAccountFromPrivateKeySync:(NSString*)pk) {
  const char* resPtr = ironfish_create_account_from_pk(NULL, [pk UTF8String]);
  NSString *res = [[NSString alloc] initWithUTF8String:resPtr];
  core_destroy_string(resPtr);
  return res;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(ironfishIsValidAddressSync:(NSString*)address) {
  const char* resPtr = ironfish_is_valid_public_address(NULL, [address UTF8String]);
  NSString *res = [[NSString alloc] initWithUTF8String:resPtr];
  core_destroy_string(resPtr);
  return res;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(aleoCreateAccountFromSeedSync:(NSString*)seed) {
  const char* resPtr = aleo_create_account_from_seed(NULL, [seed UTF8String]);
  NSString *res = [[NSString alloc] initWithUTF8String:resPtr];
  core_destroy_string(resPtr);
  return res;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(aleoCreateAccountFromPrivateKeySync:(NSString*)pk) {
  const char* resPtr = aleo_create_account_from_pk(NULL, [pk UTF8String]);
  NSString *res = [[NSString alloc] initWithUTF8String:resPtr];
  core_destroy_string(resPtr);
  return res;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(aleoIsValidAddressSync:(NSString*)address) {
  const char* resPtr = aleo_is_valid_public_address(NULL, [address UTF8String]);
  NSString *res = [[NSString alloc] initWithUTF8String:resPtr];
  core_destroy_string(resPtr);
  return res;
}

RCT_EXTERN_METHOD(spaceMeshAddressFromPubKey:(NSString*)pub resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(spaceMeshAddressFromPubKeySync:(NSString*)pub) {
  return FoxSpaceMeshAddressFromPubKey(pub);
}
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(spaceMeshStringToAddressSync:(NSString*)address) {
  return FoxSpaceMeshStringToAddress(address);
}

RCT_EXTERN_METHOD(spaceMeshCreateTransaction:(NSString*)pk to:(NSString*)to amount:(NSString*)amount nonce:(NSString*)nonce gasPrice:(NSString*)gasPrice genesisID:(NSString*)genesisID resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(spaceMeshSelfSpawnTx:(NSString*)pk nonce:(NSString*)nonce gasPrice:(NSString*)gasPrice genesisID:(NSString*)genesisID resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(polkadotScrypt:(NSDictionary*)params resolve:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
  NSString *passphrase = [params[@"passphrase"] stringValue];
  NSString *salt = [params[@"salt"] stringValue];
  NSInteger log2_n = [params[@"log2_n"] unsignedIntValue];
  NSInteger r = [params[@"r"] unsignedIntValue];
  NSInteger p = [params[@"p"] unsignedIntValue];

  const char* resPtr = polkadot_scrypt(NULL, [passphrase UTF8String], [salt UTF8String], log2_n, r, p);
  NSString *res = [[NSString alloc] initWithUTF8String:resPtr];
  resolve(res);
}

@end
