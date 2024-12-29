package com.foxwallet.core;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReadableMap;

import fox.Fox;
public class WalletCoreModule extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;

    static {
        System.loadLibrary("core");
    }

    public WalletCoreModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    private void rejectWithException(Promise promise, String code, Exception e) {
        String[] sp = e.getMessage().split(": ");
        String s = sp[sp.length - 1].trim().replace("\"", "");
        promise.reject(code, s);
    }

    @Override
    public String getName() {
        return "WalletCore";
    }

    @ReactMethod
    public void spaceMeshAddressFromPubKey(String pubkey, Promise promise) {
        promise.resolve(Fox.spaceMeshAddressFromPubKey(pubkey));
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String spaceMeshAddressFromPubKeySync(String pubkey) {
        return Fox.spaceMeshAddressFromPubKey(pubkey);
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String spaceMeshStringToAddressSync(String address) {
        return Fox.spaceMeshStringToAddress(address);
    }

    @ReactMethod
    public void spaceMeshCreateTransaction(String privateKey, String to, String amount,
                                           String nouce, String gasPrice, String genesisID,
                                           Promise promise) {
        promise.resolve(Fox.spaceMeshCreateTransaction(privateKey, to, amount, nouce, gasPrice,
          genesisID));
    }

    @ReactMethod
    public void spaceMeshSelfSpawnTx(String privateKey, String nouce, String gasPrice, String genesisID,
                                           Promise promise) {
        promise.resolve(Fox.spaceMeshSelfSpawnTx(privateKey, nouce, gasPrice,
          genesisID));
    }

    @ReactMethod
    public void ironfishCreateAccount(Promise promise) {
        promise.resolve(ironfishCreateAccountInternal());
    }

    @ReactMethod
    public void ironfishCreateAccountFromPrivateKey(String pk, Promise promise) {
        promise.resolve(ironfishCreateAccountFromPrivateKeyInternal(pk));
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String ironfishCreateAccountFromPrivateKeySync(String pk) {
        return ironfishCreateAccountFromPrivateKeyInternal(pk);
    }

    @ReactMethod
    public void ironfishSignTransaction(String rawTx, String pk, Promise promise) {
        promise.resolve(ironfishSignTransactionInternal(rawTx, pk));
    }

    @ReactMethod
    public void ironfishInitSaplingParams(String mintParamsPath, String spendParamsPath, String outputParamsPath, Promise promise) {
        promise.resolve(ironfishInitSaplingParamsInternal(mintParamsPath, spendParamsPath, outputParamsPath));
    }

    @ReactMethod
    public void ironfishIsValidAddress(String address, Promise promise) {
        promise.resolve(ironfishIsValidAddressInternal(address));
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String ironfishIsValidAddressSync(String address) {
        return ironfishIsValidAddressInternal(address);
    }

    @ReactMethod
    public void aleoCreateAccountFromSeed(String seed, Promise promise) {
        promise.resolve(aleoCreateAccountFromSeedInternal(seed));
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String aleoCreateAccountFromSeedSync(String seed) {
        return aleoCreateAccountFromSeedInternal(seed);
    }

    @ReactMethod
    public void aleoCreateAccountFromPrivateKey(String pk, Promise promise) {
        promise.resolve(aleoCreateAccountFromPrivateKeyInternal(pk));
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String aleoCreateAccountFromPrivateKeySync(String pk) {
        return aleoCreateAccountFromPrivateKeyInternal(pk);
    }

    @ReactMethod
    public void aleoIsValidAddress(String address, Promise promise) {
        promise.resolve(aleoIsValidAddressInternal(address));
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public String aleoIsValidAddressSync(String address) {
        return aleoIsValidAddressInternal(address);
    }

    @ReactMethod
    public void aleoDecryptRecord(String ciphertext, String vk, Promise promise) {
        promise.resolve(aleoDecryptRecordInternal(ciphertext, vk));
    }

    @ReactMethod
    public void aleoDeserializeCreditsRecord(String recordStr, Promise promise) {
        promise.resolve(aleoDeserializeCreditsRecordInternal(recordStr));
    }

    @ReactMethod
    public void aleoSignMessage(String pk, String message, Promise promise) {
        promise.resolve(aleoSignMessageInternal(pk, message));
    }

    @ReactMethod
    public void aleoGenerateProverFiles(String dir, String rpc_url, String network, String program_id, String function_name, String prover_file_path, String verifier_file_path, Promise promise) {
        promise.resolve(aleoGenerateProverFilesInternal(dir, rpc_url, network, program_id, function_name, prover_file_path, verifier_file_path));
    }

    @ReactMethod
    public void aleoExecuteProgram(String dir, String rpc_url, String network, String pk, String program_id, String function_name, String inputs, String fee_record, String base_fee, String priority_fee, String prover_file_path, String verifier_file_path, String fee_prover_file_path, String fee_verifier_file_path, Promise promise) {
        promise.resolve(aleoExecuteProgramInternal(dir, rpc_url, network, pk, program_id, function_name, inputs, fee_record, base_fee, priority_fee, prover_file_path, verifier_file_path, fee_prover_file_path, fee_verifier_file_path));
    }

    @ReactMethod
    public void aleoParseRecord(String plaintext, Promise promise) {
        promise.resolve(aleoParseRecordInternal(plaintext));
    }

    @ReactMethod
    public void aleoHashBhp256(String str, Promise promise) {
        promise.resolve(aleoHashBhp256Internal(str));
    }

    @ReactMethod
    public String polkadotScrypt(ReadableMap params, Promise promise) {
        String password = params.getString("passphrase");
        String salt = params.getString("salt");
        int log2_n = params.getInt("log2_n");
        int r = params.getInt("r");
        int p = params.getInt("p");
        promise.resolve(polkadotScryptInternal(password, salt, log2_n, r, p));
    }

    private static native String ironfishCreateAccountInternal();

    private static native String ironfishCreateAccountFromPrivateKeyInternal(String pk);

    private static native String ironfishSignTransactionInternal(String rawTx, String pk);

    private static native String ironfishInitSaplingParamsInternal(String mintParamsPath, String spendParamsPath, String outputParamsPath);

    private static native String ironfishIsValidAddressInternal(String address);

    private static native String aleoCreateAccountFromPrivateKeyInternal(String pk);

    private static native String aleoCreateAccountFromSeedInternal(String seed);

    private static native String aleoIsValidAddressInternal(String address);

    private static native String aleoDecryptRecordInternal(String ciphertext, String vk);
    private static native String aleoDeserializeCreditsRecordInternal(String recordStr);

    private static native String aleoSignMessageInternal(String pk, String message);

    private static native String aleoGenerateProverFilesInternal(String dir, String rpc_url, String network, String program_id, String function_name, String prover_file_path, String verifier_file_path);

    private static native String aleoExecuteProgramInternal(String dir, String rpc_url, String network, String pk, String program_id, String function_name, String inputs, String fee_record, String base_fee, String priority_fee, String prover_file_path, String verifier_file_path, String fee_prover_file_path, String fee_verifier_file_path);

    private static native String aleoParseRecordInternal(String plaintext);

    private static native String aleoHashBhp256Internal(String str);

    private static native String polkadotScryptInternal(String password_str, String salt_str, int log2_n, int r, int p);
}
