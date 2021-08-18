package bluecrystal.deps.pkcs;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PkcsUtil {
	static final Logger LOG = LoggerFactory.getLogger(PkcsUtil.class);

	public static final String[] DIGITAL_SIGNATURE_ALGORITHM_NAME = { "SHA1withRSA", "SHA224withRSA", "SHA256withRSA",
			"SHA384withRSA", "SHA512withRSA" };

	protected String signFileSignPol(String lastFilePath2, String userPIN2, int alg, String orig)
			throws Exception, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, InvalidKeyException, SignatureException {
		PrivateKey privateKey = PkiHelper.loadPrivFromP12(lastFilePath2, userPIN2);
		X509Certificate certificate = PkiHelper.loadCertFromP12(lastFilePath2, userPIN2);
		LOG.debug("Certificate: ");
		LOG.debug(certificate.getSubjectDN().getName());
		LOG.debug(certificate.getNotBefore() + " -> " + certificate.getNotAfter());

		return performSign(privateKey, certificate, alg, orig);
	}

	public String performSign(PrivateKey privateKey, X509Certificate certificate, int alg, String orig)
			throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
		Signature sig = Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[alg]);
		sig.initSign(privateKey);

		byte[] decodeOrig = Base64.getDecoder().decode(orig);
		sig.update(decodeOrig);
		byte[] dataSignature = sig.sign();

		String result = Base64.getEncoder().encodeToString(dataSignature);
		LOG.debug("Assinatura: ");
		LOG.debug(result);

		// Verify signature
		Signature verificacion = Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[alg]);
		verificacion.initVerify(certificate);
		verificacion.update(decodeOrig);
		if (verificacion.verify(dataSignature)) {
			LOG.debug("Signature verification Succeeded!");
		} else {
			LOG.debug("Signature verification FAILED!");
		}
		return result;
	}

}
