RSA enabled branch of the WoT-plugin for freenet

Currently keys are generated when either adding a new identity, or recreating an identity.
Restoring an existing RSA-enabled identity has not been verified to work as of yet... (hint)

The public key will be added as a WoT property to your identity (RSAPublicKey). The private key is exposed over FCP for getOwnIdentity etc. as an additional property.
The String consists of 2 base64 encoded byte[]'s each representing a BigInteger (mod and exp) 

Please backup your current WoT-database before trying this branch!

