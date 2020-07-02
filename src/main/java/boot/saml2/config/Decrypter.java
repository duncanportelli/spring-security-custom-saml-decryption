package boot.saml2.config;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.google.common.base.Strings;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLCipherInput;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import java.security.Key;
import javax.annotation.Nonnull;
import javax.crypto.spec.SecretKeySpec;

public class Decrypter extends org.opensaml.saml.saml2.encryption.Decrypter {

    private final Logger log = LoggerFactory.getLogger(Decrypter.class);

    /**
     * Constructor.
     *
     * @param newResolver       resolver for data encryption keys.
     * @param newKEKResolver    resolver for key encryption keys.
     * @param newEncKeyResolver resolver for EncryptedKey elements
     */
    public Decrypter(KeyInfoCredentialResolver newResolver,
                     KeyInfoCredentialResolver newKEKResolver,
                     EncryptedKeyResolver newEncKeyResolver) {
        super(newResolver, newKEKResolver, newEncKeyResolver);
    }

    /**
     * Decrypts the supplied EncryptedKey and returns the resulting Java security Key object. The algorithm of the
     * decrypted key must be supplied by the caller based on knowledge of the associated EncryptedData information.
     *
     * @param encryptedKey encrypted key element containing the encrypted key to be decrypted
     * @param algorithm the algorithm associated with the decrypted key
     * @param kek the key encryption key with which to attempt decryption of the encrypted key
     * @return the decrypted key
     * @throws DecryptionException exception indicating a decryption error
     */
    @Nonnull
    @Override
    public Key decryptKey(@Nonnull EncryptedKey encryptedKey, @Nonnull String algorithm, Key kek) throws DecryptionException {
        if (Strings.isNullOrEmpty(algorithm)) {
            log.error("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
            throw new DecryptionException("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
        }

        validateAlgorithms(encryptedKey);

        try {
            checkAndMarshall(encryptedKey);
        } catch (final DecryptionException e) {
            log.error("Error marshalling EncryptedKey for decryption", e);
            throw e;
        }
        preProcessEncryptedKey(encryptedKey, algorithm, kek);

        final XMLCipher xmlCipher;
        try {
            if (getJCAProviderName() != null) {
                xmlCipher = XMLCipher.getProviderInstance(getJCAProviderName());
            } else {
                xmlCipher = XMLCipher.getInstance();
            }
            xmlCipher.init(XMLCipher.UNWRAP_MODE, kek);
        } catch (final XMLEncryptionException e) {
            log.error("Error initialzing cipher instance on key decryption", e);
            throw new DecryptionException("Error initialzing cipher instance on key decryption", e);
        }

        final org.apache.xml.security.encryption.EncryptedKey encKey;
        try {
            final Element targetElement = encryptedKey.getDOM();
            encKey = xmlCipher.loadEncryptedKey(targetElement.getOwnerDocument(), targetElement);
        } catch (final XMLEncryptionException e) {
            log.error("Error when loading library native encrypted key representation", e);
            throw new DecryptionException("Error when loading library native encrypted key representation", e);
        }

        try {
            final Key key = decryptKey(encKey, algorithm);
//            final Key key = xmlCipher.decryptKey(encKey, algorithm);
            if (key == null) {
                throw new DecryptionException("Key could not be decrypted");
            }
            return key;
        } catch (final XMLEncryptionException e) {
            log.error("Error decrypting encrypted key", e);
            throw new DecryptionException("Error decrypting encrypted key", e);
        }  catch (final Exception e) {
            // Catch anything else, esp. unchecked RuntimeException, and convert to our checked type.
            // BouncyCastle in particular is known to throw unchecked exceptions for what we would
            // consider "routine" failures.
            throw new DecryptionException("Probable runtime exception on decryption:" + e.getMessage(), e);
        }
    }

    /**
     * Decrypt a key from a passed in EncryptedKey structure
     *
     * @param encryptedKey Previously loaded EncryptedKey that needs
     * to be decrypted.
     * @param algorithm Algorithm for the decryption
     * @return a key corresponding to the given type
     * @throws XMLEncryptionException
     */
    public Key decryptKey(org.apache.xml.security.encryption.EncryptedKey encryptedKey, String algorithm)
        throws XMLEncryptionException {

        if (log.isDebugEnabled()) {
            log.debug("Decrypting key from previously loaded EncryptedKey...");
        }

        if (algorithm == null) {
            throw new XMLEncryptionException("Cannot decrypt a key without knowing the algorithm");
        }

        // Obtain the encrypted octets
        XMLCipherInput cipherInput = new XMLCipherInput(encryptedKey);
        byte[] encryptedBytes = cipherInput.getBytes();

        String jceKeyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithm);
        if (log.isDebugEnabled()) {
            log.debug("JCE Key Algorithm: " + jceKeyAlgorithm);
        }

        String clientID = "";
        String clientCred = "";
        String tenantId = "";
        String keyIdentifier = "";
        String keyAlgorithm = "RSA1_5";

        ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
            .clientId(clientID)
            .clientSecret(clientCred)
            .tenantId(tenantId)
            .build();

        CryptographyClient keyClient = new CryptographyClientBuilder()
            .credential(clientSecretCredential)
            .keyIdentifier(keyIdentifier)
            .buildClient();

        byte[] decryptedBytes = keyClient.unwrapKey(KeyWrapAlgorithm.fromString(keyAlgorithm), encryptedBytes).getKey();

        return new SecretKeySpec(decryptedBytes, 0, decryptedBytes.length, jceKeyAlgorithm);
    }

}
