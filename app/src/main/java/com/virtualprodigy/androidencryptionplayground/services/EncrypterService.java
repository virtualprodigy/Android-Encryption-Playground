package com.virtualprodigy.androidencryptionplayground.services;

import android.app.IntentService;
import android.content.Intent;
import android.os.Bundle;
import android.os.ResultReceiver;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Enumeration;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;

public class EncrypterService extends IntentService {
    public static final int RESULT_CODE_ENCRYPT_OK = 1;
    public static final int RESULT_CODE_DECRYPT_OK = 2;
    public static final int RESULT_CODE_FAILED = -1;

    public static final String ACTION_ENCRYPT_DATA = "action_encrypt_data";
    public static final String ACTION_DECRYPT_DATA = "action_decrypt_data";

    public static final String BUNDLE_DATA_TO_ENCRYPT = "bundle_data_to_encrypt";
    public static final String BUNDLE_DATA_TO_DECRYPT = "bundle_data_to_decrypt";
    public static final String BUNDLE_ENCRYPTED_DATA = "bundle_encrypted_data";
    public static final String BUNDLE_DECRYPTED_DATA = "bundle_decrypted_data";
    public static final String BUNDLE_MASTER_KEY = "bundle_master_key";
    public static final String BUNDLE_RESULT_RECEIVER = "bundle_result_receiver";

    private final String TAG = this.getClass().getSimpleName();
    private final String PBKDF2_ALGORITHM = "PBKDF2withHmacSHA1And8BIT";
    private final int PBKDF2_ITERATION_COUNT = 1050;
    private final int PBKDF2_KEY_LENGTH = 256;
    private static final int PBKDF2_IV_LENGTH = 128;

    //how to handle the keys locally
    static byte[]  pbkdf2SecuredKey;
    static byte[] pbkdf2SecuredIV;

    private static final Random random= new SecureRandom();

    public EncrypterService() {

        super("EncrypterService");
    }


    @Override
    protected void onHandleIntent(Intent intent) {
        String action = null;
        if (intent != null) {
            action = intent.getAction();
        }

        ResultReceiver resultReceiver = intent.getParcelableExtra(BUNDLE_RESULT_RECEIVER);
        String masterKey = intent.getStringExtra(BUNDLE_MASTER_KEY);
        switch (action) {
            case ACTION_ENCRYPT_DATA:

                String plainText = intent.getStringExtra(BUNDLE_DATA_TO_ENCRYPT);
                String encryptedString = encryptData(plainText.getBytes(), masterKey);

                if (encryptedString != null) {

                    Bundle bundle = new Bundle();
                    bundle.putString(BUNDLE_ENCRYPTED_DATA, encryptedString);
                    resultReceiver.send(RESULT_CODE_ENCRYPT_OK, bundle);
                } else {
                    resultReceiver.send(RESULT_CODE_FAILED, null);
                }
                break;

            case ACTION_DECRYPT_DATA:
                String cipherText = intent.getStringExtra(BUNDLE_DATA_TO_DECRYPT);
                String decryptedString = decryptData(cipherText.getBytes(), pbkdf2SecuredKey, pbkdf2SecuredIV);

                if(decryptedString != null){
                    Bundle bundle = new Bundle();
                    bundle.putString(BUNDLE_DECRYPTED_DATA, decryptedString);
                    resultReceiver.send(RESULT_CODE_DECRYPT_OK, bundle);
                } else {
                    resultReceiver.send(RESULT_CODE_FAILED, null);
                }
                break;

            default:
                break;
        }

    }

    /**
     *
     * @param plainText - data to encrypt
     * @param encrpytionKey - Encryption Key
     * @return
     */
    private String encryptData(byte [] plainText, String encrpytionKey) {

        try {

            pbkdf2SecuredKey = generateSecretKey(encrpytionKey);
            pbkdf2SecuredIV = generateSecureIV(encrpytionKey);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(pbkdf2SecuredIV);
            SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] cipherBytes = cipher.doFinal(plainText);
            return Base64.encodeToString(cipherBytes, Base64.DEFAULT);

        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed To encrypt the data", e);
            return null;
        } catch (NoSuchPaddingException e) {
            Log.e(TAG, "Failed To encrypt the data", e);
            return null;
        } catch (InvalidKeyException e) {
            Log.e(TAG, "Failed To encrypt the data", e);
            return null;
        } catch (BadPaddingException e) {
            Log.e(TAG, "Failed To encrypt the data", e);
            return null;
        } catch (IllegalBlockSizeException e) {
            Log.e(TAG, "Failed To encrypt the data", e);
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, "Failed To encrypt the data", e);
            return null;
        }
    }

    /**
     *
     * @param cipherBytes - data to be decrypted
     * @param pbkdf2SecuredKey - must be the key used to encrypt the data
     * @param pbkdf2SecuredIV - must be the IV used to encrypt the data
     * @return
     */
    private String decryptData(byte [] cipherBytes, byte [] pbkdf2SecuredKey, byte [] pbkdf2SecuredIV) {

        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(pbkdf2SecuredIV);
            SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] clearTextBytes = cipher.doFinal(Base64.decode(cipherBytes, Base64.DEFAULT));
            return new String(clearTextBytes);

        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed To decrypt the data", e);
            return null;
        } catch (NoSuchPaddingException e) {
            Log.e(TAG, "Failed To decrypt the data", e);
            return null;
        } catch (InvalidKeyException e) {
            Log.e(TAG, "Failed To decrypt the data", e);
            return null;
        } catch (BadPaddingException e) {
            Log.e(TAG, "Failed To decrypt the data", e);
            return null;
        } catch (IllegalBlockSizeException e) {
            Log.e(TAG, "Failed To decrypt the data", e);
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, "Failed To decrypt the data", e);
            return null;
        }
    }

    private byte[] generateSecretKey(String password){
        byte[] secretKey = secureSecretKeyWithPBKDF2(password, PBKDF2_KEY_LENGTH);
        String encodedString = Hex.encodeHexString(secretKey);
        return secretKey;
    }

    /**
     * Need a different IV for each value under the same key
     * https://crypto.stackexchange.com/questions/50782/what-size-of-initialization-vector-iv-is-needed-for-aes-encryption
     * @param password
     * @return
     */
    private byte[] generateSecureIV(String password){
        byte[] secretKey = secureSecretKeyWithPBKDF2(password, PBKDF2_IV_LENGTH);
        String encodedString = Hex.encodeHexString(secretKey);
        return secretKey;
    }
    /**
     * Generating a random salt for the password
     *
     * https://security.stackexchange.com/questions/11221/how-big-should-salt-be
     *
     */
    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[128];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Generates the secret key based on the provided password
     * Number of Iterations
     * https://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256
     * @param password
     */
    private byte [] secureSecretKeyWithPBKDF2(String password, int length){
        try {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), generateRandomSalt(), PBKDF2_ITERATION_COUNT, length);
            SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
            byte [] secret = secretKey.getEncoded();
            storeAndroidKey(secret);
            return secret;

        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed To secure the key", e);
            return null;
        } catch (InvalidKeySpecException e) {
            Log.e(TAG, "Failed To secure the key", e);
            return null;
        }
    }

    private void storeAndroidKey(byte [] encryptedKey) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            SecretKey key = new SecretKeySpec(encryptedKey, 0, encryptedKey.length, "AES");
            keyStore.setKeyEntry("MasterKey", key, null,null);
            Enumeration<String> aliases = keyStore.aliases();

            while(aliases.hasMoreElements()){
                String keyAlias = new String(aliases.nextElement().getBytes());
                Log.i(TAG, "Failed to get Keystore, KeyStoreException" + keyAlias);
            }

        } catch (KeyStoreException e) {
            Log.e(TAG, "Failed to get Keystore, KeyStoreException", e);
        } catch (CertificateException e) {
            Log.e(TAG, "Failed to get Keystore, CertificateException", e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed to get Keystore, NoSuchAlgorithmException", e);
        } catch (IOException e) {
            Log.e(TAG, "Failed to get Keystore, IOException", e);
        }


    }
}
