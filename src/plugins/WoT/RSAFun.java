package plugins.WoT;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

//import org.bouncycastle.jce.provider.BouncyCastleProvider; Needs signed jar to work with Java JCE

import plugins.WoT.exceptions.InvalidParameterException;

import freenet.crypt.SHA256;
import freenet.crypt.UnsupportedCipherException;
import freenet.crypt.ciphers.Rijndael;

public class RSAFun {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, UnsupportedCipherException, InvalidParameterException
	{
		//Security.addProvider(new BouncyCastleProvider());
		final String message = "This is a test";
		
		//create RSA keypair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();
		Key publicKey = kp.getPublic();
		Key privateKey = kp.getPrivate();
		
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

		
		String key = RSAUtils.RSAKeyParametersToString(pub.getModulus(), pub.getPublicExponent());
		System.out.println(key);
		
		RSAUtils.readRSAKeyFromString(key, RSAPublicKeySpec.class);
		
		/*
		saveToFile("/tmp/public.key", pub.getModulus(), pub.getPublicExponent());
		saveToFile("/tmp/private.key", priv.getModulus(), priv.getPrivateExponent());

		//encrypt data using RSA public key
		byte[] encrypted = rsaEncrypt(message.getBytes());
		System.out.println("encrypted: " + encrypted);
		
		//decrypt data using RSA private key
		System.out.println("decrypted: " + new String(rsaDecrypt(encrypted)));

		//create a random key for a streaming cypher
		//FIXME: howto generate a random key?
		Rijndael aes = new Rijndael(256, 256);
		MessageDigest md = SHA256.getMessageDigest();
		md.update("RANDOM SEED".getBytes());
        md.update("SALT".getBytes());
        byte[] aes_key = md.digest();

        byte[] input = new byte[32];
        System.arraycopy(message.getBytes(), 0, input, 0, message.getBytes().length);
        byte[] output = new byte[input.length];
        
		//encrypt data using the streaming cypher
        aes.initialize(aes_key);
        aes.encipher(input, output);
        
		//decrypt data using the streaming cypher
        aes.decipher(output, input);
        System.out.println("AES encrypted: " + new String(output));
        System.out.println("AES decrypted: " + new String(input));
        
		//encrypt the streaming cypher key using RSA
		byte[] encrypted_aes_key = rsaEncrypt(aes_key);
        System.out.println("encrypted aes key size (bytes): " + encrypted_aes_key.length);
        
		//apply the streaming cypher and store the key & the data using a Bucket
		byte[] data = new byte[encrypted_aes_key.length+output.length];
        */
        
		//profit!
	}
	
	public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
			  ObjectOutputStream oout = new ObjectOutputStream(
			    new BufferedOutputStream(new FileOutputStream(fileName)));
			  try {
			    oout.writeObject(mod);
			    oout.writeObject(exp);
			  } catch (Exception e) {
			    throw new IOException("Unexpected error", e);
			  } finally {
			    oout.close();
			  }
			}

	public static PublicKey readKeyFromFile(String keyFileName) throws IOException {
		  InputStream in = new FileInputStream(keyFileName);
		  ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
		  try {
		    BigInteger m = (BigInteger) oin.readObject();
		    BigInteger e = (BigInteger) oin.readObject();
		    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PublicKey pubKey = fact.generatePublic(keySpec);
		    return pubKey;
		  } catch (Exception e) {
		    throw new RuntimeException("Spurious serialisation error", e);
		  } finally {
		    oin.close();
		  }
		}
	
	public static byte[] rsaEncrypt(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		  PublicKey pubKey = readKeyFromFile("/tmp/public.key");
		  Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
		  cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		  byte[] cipherData = cipher.doFinal(data);
		  return cipherData;
		}
	
	public static byte[] rsaDecrypt(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		  PublicKey privKey = readKeyFromFile("/tmp/private.key");
		  Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
		  cipher.init(Cipher.DECRYPT_MODE, privKey);
		  byte[] cipherData = cipher.doFinal(data);
		  return cipherData;
		}
	
}
