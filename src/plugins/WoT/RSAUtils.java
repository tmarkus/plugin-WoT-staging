package plugins.WoT;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import plugins.WoT.exceptions.InvalidParameterException;
import freenet.support.Base64;

public class RSAUtils {

	
	public static String RSAKeyParametersToString(BigInteger mod, BigInteger exp)
	{
		ObjectOutputStream oout = null;  
		try {
			
			ByteArrayOutputStream data = new ByteArrayOutputStream();
			oout = new ObjectOutputStream(new BufferedOutputStream(data));
		    
			oout.writeObject(mod.toByteArray());
		    oout.writeObject(exp.toByteArray());
		    data.flush();
		    oout.close();
		    
		    byte[] result = data.toByteArray();
		    return Base64.encode(result);
		} catch (Exception e) {
		     e.printStackTrace();
		     return null;
		}
	}

	public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException
	{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();
		return kp;
	}

	public static void readRSAKeyFromString(String key, @SuppressWarnings("rawtypes") Class type) throws InvalidParameterException
	{
		ObjectInputStream oin = null;
		try {
			oin = new ObjectInputStream(new BufferedInputStream(new ByteArrayInputStream(Base64.decode(key))));
		    BigInteger m = new BigInteger((byte[]) oin.readObject());
		    BigInteger e = new BigInteger((byte[]) oin.readObject());
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    
		    if (type == RSAPublicKeySpec.class)
		    {
			    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
			    fact.generatePublic(keySpec);
		    }
		    else
		    {
			    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
			    fact.generatePrivate(keySpec);
		    }
		} catch (Exception e) {
			e.printStackTrace();
			throw new InvalidParameterException("One or more of the RSA keys provided cannot be be parsed");
		}
	}

	
}
