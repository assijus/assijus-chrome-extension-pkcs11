/*
    Blue Crystal: Document Digital Signature Tool
    Copyright (C) 2007-2015  Sergio Leal

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package bluecrystal.chrome.sign;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import bluecrystal.deps.pkcs.PkcsRef;
import bluecrystal.deps.pkcs.PkcsUtil;
import bluecrystal.deps.pkcs.PkiHelper;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.util.DerOutputStream;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

public class PkcsWrapper extends PkcsUtil {
	static final Logger LOG = LoggerFactory.getLogger(PkcsWrapper.class);

	private static final int ALG_NO_SP = 99;

	private static final String SYSTEM32 = "\\System32\\";

	public static final int STORE_PKCS11 = 0;
	public static final int STORE_FILE_UI = 1;
	public static final int STORE_FILE = 2;
	public static final int STORE_APPLE = 3;

	private static PkcsRef pkcsRef = new PkcsRef();

	public String result;
	private String caption;
	private String certAlias;
	public String orig;
	private String userPIN;
	private String lastFilePath;
	public int alg;
	private int store;

	private int curKeySize;
	private String curSubject;

	private String[] pkcs11LibName = null;
	private String[] otherPath = null;
	private static String name = null;

	public PkcsWrapper(String pkcsLibName, String otherPath) {
		super();
		this.pkcs11LibName = pkcsLibName.split(";");
		this.otherPath = otherPath.split(";");

		// this.fileChooser = new FileChooser();
	}

	public int getCurKeySize() {
		return curKeySize;
	}

	public String getCurSubject() {
		return curSubject;
	}

	public static KeyStore getKeyStore() {
		return pkcsRef.getKeyStore();
	}

	public static String getConfigString() {
		return pkcsRef.getConfigString();
	}

	public String getLastFilePath() {
		return lastFilePath;
	}

	public void setLastFilePath(String lastFilePath) {
		this.lastFilePath = lastFilePath;
	}

	public int getStore() {
		return store;
	}

	public void setStore(int store) {
		this.store = store;
	}

	public int getAlg() {
		return alg;
	}

	public void setAlg(int alg) {
		this.alg = alg;
	}

	public String getUserPIN() {
		return userPIN;
	}

	public void setUserPIN(String userPIN) {
		this.userPIN = userPIN;
	}

	public void setOrig(String orig) {
		this.orig = orig;
	}

	public String getCertAlias() {
		return certAlias;
	}

	public void setCertAlias(String certAlias) {
		this.certAlias = certAlias;
	}

	public String getCaption() {
		return caption;
	}

	public void setCaption(String caption) {
		this.caption = caption;
	}

	private List<CertId> listCerts;

	public String getResult() {
		return result;
	}

	public void sign() throws Exception {

		LOG.debug("sign");
		switch (this.store) {
			case STORE_PKCS11:
				signpkcs();
				break;
				
			case STORE_APPLE:
				signpkcs();
				break;
	
			case STORE_FILE_UI:
				signFile();
				break;
	
			case STORE_FILE:
				signFile();
				break;
	
			default:
				LOG.debug("opps " + this.store);
				break;
		}
	}

	private void signFile() throws Exception {
		if (this.alg != ALG_NO_SP) {
			signFileSignPol();
		} else {
			signFileNoSignPol();
		}
		if (pkcsRef.getPkcsProvider() != null) {
			Security.removeProvider(pkcsRef.getPkcsProvider().getName());
		}
	}

	private void signFileSignPol() throws Exception {
		LOG.debug("signFileSignPol");

		String lastFilePath2 = this.lastFilePath;
		String userPIN2 = this.userPIN;
		this.result = signFileSignPol(lastFilePath2, userPIN2, this.alg, this.orig);

	}

	private void signFileNoSignPol() throws Exception {
		LOG.debug("signFileNoSignPol");
		// LOAD CERT
		PrivateKey privateKey = PkiHelper.loadPrivFromP12(this.lastFilePath, this.userPIN);
		X509Certificate certificate = PkiHelper.loadCertFromP12(this.lastFilePath, this.userPIN);
		// Sign data
		Signature sig = Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[0]);
		// sha1 only
		sig.initSign(privateKey);
		sig.update(Base64.getDecoder().decode(orig));
		byte[] signedData = sig.sign();

		// load X500Name
		X500Name xName = X500Name.asX500Name(certificate.getSubjectX500Principal());
		// load serial number
		BigInteger serial = certificate.getSerialNumber();
		// laod digest algorithm
		AlgorithmId digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid);
		// load signing algorithm
		AlgorithmId signAlgorithmId = new AlgorithmId(AlgorithmId.RSAEncryption_oid);

		// Create SignerInfo:
		SignerInfo sInfo = new SignerInfo(xName, serial, digestAlgorithmId, signAlgorithmId, signedData);
		// Create ContentInfo:
		// ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID,
		// new DerValue(DerValue.tag_OctetString, dataToSign));
		ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, null);
		// Create PKCS7 Signed data
		PKCS7 p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId }, cInfo, new X509Certificate[] { certificate },
				new SignerInfo[] { sInfo });
		// Write PKCS7 to bYteArray
		ByteArrayOutputStream bOut = new DerOutputStream();
		p7.encodeSignedData(bOut);
		byte[] encodedPKCS7 = bOut.toByteArray();

		result = Base64.getEncoder().encodeToString(encodedPKCS7);
		LOG.debug("result:" + result);
	}

	private void signpkcs() throws Exception {
		if (this.alg != ALG_NO_SP) {
			signpkcsSignPol();
		} else {
			signpkcsNoSignPol();
		}
		// Security.removeProvider(pkcs11Ref.getPkcs11Provider().getName());
	}

	private void signpkcsNoSignPol() throws Exception {

		// LOAD CERT
		PrivateKey privateKey = (PrivateKey) pkcsRef.getKeyStore().getKey(this.getCertAlias(), "".toCharArray());
		X509Certificate certificate = (X509Certificate) pkcsRef.getKeyStore().getCertificate(this.getCertAlias());
		// Sign data
		Signature sig = Signature.getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[0]);
		// sha1 only
		sig.initSign(privateKey);
		sig.update(Base64.getDecoder().decode(orig));
		byte[] signedData = sig.sign();

		// load X500Name
		X500Name xName = X500Name.asX500Name(certificate.getSubjectX500Principal());
		// load serial number
		BigInteger serial = certificate.getSerialNumber();
		// laod digest algorithm
		AlgorithmId digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid);
		// load signing algorithm
		AlgorithmId signAlgorithmId = new AlgorithmId(AlgorithmId.RSAEncryption_oid);

		// Create SignerInfo:
		SignerInfo sInfo = new SignerInfo(xName, serial, digestAlgorithmId, signAlgorithmId, signedData);
		// Create ContentInfo:
		// ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID,
		// new DerValue(DerValue.tag_OctetString, dataToSign));
		ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, null);
		// Create PKCS7 Signed data
		PKCS7 p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId }, cInfo, new X509Certificate[] { certificate },
				new SignerInfo[] { sInfo });
		// Write PKCS7 to bYteArray
		ByteArrayOutputStream bOut = new DerOutputStream();
		p7.encodeSignedData(bOut);
		byte[] encodedPKCS7 = bOut.toByteArray();

		result = Base64.getEncoder().encodeToString(encodedPKCS7);
	}

	// private void signp11NoSignPolWithChain() {
	// //
	// http://security.stackexchange.com/questions/13910/pkcs7-encoding-in-java-without-external-libs-like-bouncycastle-etc
	// try {
	// // LOAD CERT
	// PrivateKey privateKey = (PrivateKey) keyStore.getKey(
	// this.getCertAlias(), "".toCharArray());
	// X509Certificate certificate = (X509Certificate) keyStore
	// .getCertificate(this.getCertAlias());
	//
	// X509Certificate[] chain = loadCertChain();
	//
	// // Sign data
	// Signature sig = Signature
	// .getInstance(DIGITAL_SIGNATURE_ALGORITHM_NAME[0]);
	// // sha1 only
	// sig.initSign(privateKey);
	// BASE64Decoder b64dec = new BASE64Decoder();
	// BASE64Encoder b64enc = new BASE64Encoder();
	// sig.update(b64dec.decodeBuffer(orig));
	// byte[] signedData = sig.sign();
	//
	// //load X500Name
	// X500Name xName =
	// X500Name.asX500Name(certificate.getSubjectX500Principal());
	// //load serial number
	// BigInteger serial = certificate.getSerialNumber();
	// //laod digest algorithm
	// AlgorithmId digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid);
	// //load signing algorithm
	// AlgorithmId signAlgorithmId = new
	// AlgorithmId(AlgorithmId.RSAEncryption_oid);
	//
	// //Create SignerInfo:
	// SignerInfo sInfo = new SignerInfo(xName, serial, digestAlgorithmId,
	// signAlgorithmId, signedData);
	// //Create ContentInfo:
	// // ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, new
	// DerValue(DerValue.tag_OctetString, dataToSign));
	// ContentInfo cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, null);
	// //Create PKCS7 Signed data
	// PKCS7 p7 = new PKCS7(new AlgorithmId[] { digestAlgorithmId }, cInfo,
	// chain,
	// new SignerInfo[] { sInfo });
	// //Write PKCS7 to bYteArray
	// ByteArrayOutputStream bOut = new DerOutputStream();
	// p7.encodeSignedData(bOut);
	// byte[] encodedPKCS7 = bOut.toByteArray();
	//
	// result = b64enc.encode(encodedPKCS7);
	//
	// } catch (Exception e) {
	// e.printStackTrace();
	// }
	//
	// }

	private X509Certificate[] loadCertChain() throws Exception {
		Certificate[] chain = pkcsRef.getKeyStore().getCertificateChain(this.getCertAlias());
		X509Certificate[] chainX509 = new X509Certificate[chain.length];

		for (int i = 0; i < chain.length; i++) {
			chainX509[i] = (X509Certificate) chain[i];
		}
		return chainX509;
	}

	private void signpkcsSignPol() throws Exception {

		// LOAD CERT
		PrivateKey privateKey = (PrivateKey) pkcsRef.getKeyStore().getKey(this.getCertAlias(), "".toCharArray());
		X509Certificate certificate = (X509Certificate) pkcsRef.getKeyStore().getCertificate(this.getCertAlias());

		this.result = performSign(privateKey, certificate, this.alg, this.orig);

	}

	private int getSlot() throws Exception {

		// "Fabrica" de Terminais PC/SC
		TerminalFactory factory;
		// Lista de Leitores PC/SC
		List terminals;

		// Adquire Fabrica de Leitores
		factory = TerminalFactory.getDefault();

		// Adquire Lista de Leitores PC/SC no Sistema
		terminals = factory.terminals().list();
		// Logger.print(false, "Lista : " + terminals);

		int i = 0;
		for (Object next : terminals) {
			CardTerminal t = (CardTerminal) next;
			// System.out.print(t.getName());
			// LOG.debug(t.isCardPresent() ? " COM" : " sem");
			if (t.isCardPresent()) {
				break;
				// card = t.connect("*");
				// CardChannel channel = card.getBasicChannel();
				//
				// int cn = channel.getChannelNumber();
				// LOG.debug("getChannelNumber(): "+cn);
				// LOG.debug("Protocol: "+card.getProtocol());
			}
			i++;

		}

		return i;
	}

	void loadKeyStore() throws Exception {
		LOG.debug("loadKeyStore");
		pkcsRef.setKeyStore(null); //reset keystore
		switch (this.store) {
			case STORE_PKCS11:
				loadKeyStorep11();
				break;
			case STORE_APPLE:
				loadKeyStoreApple();
				break;
	
			default:
				LOG.debug("opps " + this.store);
				break;
		}
	}

	private void loadKeyStorep11()
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

		LOG.debug("loadKeyStorep11");
		name = "ittru";
		
		String systemWindowsDir = System.getenv("SystemRoot");

		List<String> paths = new ArrayList<String>();
		if (systemWindowsDir != null) {
			paths.add(systemWindowsDir + SYSTEM32);
		}
		for (String next : this.otherPath) {
			paths.add(verifyPath(next));
		}

		for (String nextPath : paths) {
			for (String next : pkcs11LibName) {
				try {
					pkcsRef.setPKCSLibrary(nextPath + next);
					LOG.debug("Carregando: " + pkcsRef.getPKCSLibrary());
					createConfigSlotListIndex();
					// Load SunPKCS#11 provider
					pkcsRef.setPkcsProvider(new sun.security.pkcs11.SunPKCS11(pkcsRef.getConfigStream()));

					Security.addProvider(pkcsRef.getPkcsProvider());
					pkcsRef.setKeyStore(KeyStore.getInstance("PKCS11"));

					LOG.debug("** FOUND!");
					printDebug();
					break;
				} catch (Exception e) {
					LOG.debug("Can't load pcks library: Ex: " + e.getLocalizedMessage());
				}
			}
		}

		pkcsRef.getKeyStore().load(null, userPIN.toCharArray());
	}
	
	private void loadKeyStoreApple() throws KeyStoreException, IOException,NoSuchAlgorithmException, CertificateException {
		try {
			LOG.debug("loadKeyStoreApple");
			pkcsRef.setKeyStore(KeyStore.getInstance("KeychainStore","Apple"));
			LOG.debug("** FOUND!");
			pkcsRef.getKeyStore().load(null, null);
			LOG.debug("** LOADED!");
			printDebug();
		} catch (Exception e) {
			LOG.debug("Can't load Apple KeyStore: Ex: " + e.getLocalizedMessage());
		}
	}

	private String verifyPath(String next) {
		if (!next.endsWith(File.separator)) {
			next = next.concat(File.separator);
		}
		return next;
	}

	private void printDebug() {
		Enumeration<Object> el = pkcsRef.getPkcsProvider().elements();
		System.err.println(" ** ELEMENTS ***");
		while (el.hasMoreElements()) {
			Object obj = el.nextElement();
			System.err.println("OBJ: " + obj);
		}
		Set<Object> chaves = pkcsRef.getPkcsProvider().keySet();
		System.err.println(" ** CHAVES ***");
		for (Object nextKey : chaves) {
			System.err.println("OBJ: " + nextKey);
		}
		System.err.println("INFO: " + pkcsRef.getPkcsProvider().getInfo());
		System.err.println("NAME: " + pkcsRef.getPkcsProvider().getName());
		pkcsRef.getPkcsProvider().list(System.err);
		Set<Service> services = pkcsRef.getPkcsProvider().getServices();
		for (Object nextObj : services.toArray()) {
			Service nextServ = (Service) nextObj;
			System.err.println(" ** SERVICE ***");
			System.err.println("Alg: " + nextServ.getAlgorithm());
			System.err.println("Class: " + nextServ.getClassName());
			System.err.println("Type: " + nextServ.getType());
			Provider prov = nextServ.getProvider();
			System.err.println(" ** PROVIDER ***");
			System.err.println("INFO: " + prov.getInfo());
			System.err.println("NAME: " + prov.getName());
			System.err.println("VERS: " + prov.getVersion());
		}
		pkcsRef.getPkcsProvider().getInfo();
	}

	public void println(String string) {
		LOG.debug("* " + string);

	}

	void createConfigSlotListIndex() {
		name = "ittru";

		int i = -1;
		try {
			i = getSlot();
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			LOG.error("can't createConfigSlotListIndex", e1);
		}
		String slotTxt = String.format("\n slotListIndex  = %d ", i);

		String ext = "attributes(*,*,*)=\n{\nCKA_TOKEN=true\nCKA_LOCAL=true\n}";
		pkcsRef.setConfigString("name = " + name.replace(' ', '_') + "\n" + "library = " + pkcsRef.getPKCSLibrary()
				+ slotTxt + "\n attributes = compatibility \n" + ext);
		byte[] configBytes = pkcsRef.getConfigString().getBytes();
		pkcsRef.setConfigStream(new ByteArrayInputStream(configBytes));
	}

	public String loadCertsJson() {
		String ret = "";
		for (CertId next : this.listCerts) {
			ret += String.format("{\"alias\":\"%s\",\"subject\":\"%s\"},\n", next.getAlias(), next.getSubjectDn());
			LOG.debug("ret:" + ret);
		}

		LOG.debug("ret:" + ret);
		// ret = ret.replace(ret.substring(ret.length() - 2), "");
		ret = ret.substring(0, ret.length() - 2);
		LOG.debug("ret:" + ret);
		return "[\n" + ret + "]\n";
	}

	public void refreshCerts() {
		this.listCerts = new ArrayList<CertId>();
		try {
			// loadKeyStore();

			int numCerts = 0;
			String alias = "";
			Enumeration aliasesEnum = pkcsRef.getKeyStore().aliases();
			while (aliasesEnum.hasMoreElements()) {
				alias = (String) aliasesEnum.nextElement();

				if (pkcsRef.getKeyStore().isKeyEntry(alias)) { //add into list only certificate with private keys
					Certificate cert = pkcsRef.getKeyStore().getCertificate(alias);
					X509Certificate x509Certificate = (X509Certificate) cert;
					
					if (isCertValid(x509Certificate)) {
						RSAPublicKey rsaPubK = (RSAPublicKey) x509Certificate.getPublicKey();
						this.listCerts.add(new CertId(alias, x509Certificate.getSubjectDN().getName(), cert.getEncoded(),
								rsaPubK.getModulus().bitLength()));
					}
				}
				numCerts++;
			}

		} catch (Exception e) {
			LOG.error("can't refreshCerts", e);
		}

	}
	
	public boolean isCertValid(X509Certificate x509Certificate) {
		try {
			x509Certificate.checkValidity();
			return true;
		}
		catch (CertificateExpiredException e) {
			return false;
		}
		catch (CertificateNotYetValidException e) {
			return false;
		}
	}

	public String getCert(String alias) {

		debugPrn("* list cert# : " + this.listCerts.size());
		for (CertId next : this.listCerts) {
			debugPrn(next.getAlias());
			if (next.getAlias().compareToIgnoreCase(alias) == 0) {
				return Base64.getEncoder().encodeToString(next.getEncoded());
			}
		}
		return null;
	}

	private static SecretKey decryptAESKey(byte[] data, PrivateKey priv) {
		SecretKey key = null;
		Cipher cipher = null;

		try {
			// initialize the cipher...
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, priv);

			// generate the aes key!
			key = new SecretKeySpec(cipher.doFinal(data), "AES");
		} catch (Exception e) {
			String x = "exception decrypting the aes key: " + e.getMessage();
			debugPrn(x);
			return null;
		}

		return key;
	}

	private static void debugPrn(String x) {
		LOG.debug(x);
	}

	void skeyDercypt() throws Exception {

		LOG.debug("sign");
		switch (this.store) {
			case STORE_PKCS11:
				skeyDercyptPkcs();
				break;
			case STORE_APPLE:
				skeyDercyptPkcs();
				break;
			case STORE_FILE_UI:
				skeyDercyptFile();
				break;
	
			case STORE_FILE:
				skeyDercyptFile();
				break;
	
			default:
				LOG.debug("opps " + this.store);
				break;
		}
	}

	private void skeyDercyptPkcs() throws Exception {

		PrivateKey privateKey = (PrivateKey) pkcsRef.getKeyStore().getKey(this.getCertAlias(), "".toCharArray());

		byte[] origBin = Base64.getDecoder().decode(this.orig);

		SecretKey Skey = decryptAESKey(origBin, privateKey);
		this.result = Base64.getEncoder().encodeToString(Skey.getEncoded());
	}

	private void skeyDercyptFile() throws Exception {

		PrivateKey privateKey = PkiHelper.loadPrivFromP12(this.lastFilePath, this.userPIN);
		byte[] origBin = Base64.getDecoder().decode(this.orig);

		SecretKey Skey = decryptAESKey(origBin, privateKey);
		this.result = Base64.getEncoder().encodeToString(Skey.getEncoded());
	}

	public static String conv(byte[] byteArray) {
		StringBuffer result = new StringBuffer();
		for (byte b : byteArray) {
			result.append(String.format("%02X", b));
		}
		return result.toString();
	}

	public int getKeySize(String alias) {
		for (CertId next : this.listCerts) {
			if (next.getAlias().compareToIgnoreCase(alias) == 0) {
				return next.getKeySize();
			}
		}
		return 0;
	}

	public String getSubject(String alias) {
		for (CertId next : this.listCerts) {
			debugPrn(next.getAlias());
			if (next.getAlias().compareToIgnoreCase(alias) == 0) {
				return next.getSubjectDn();
			}
		}
		return null;
	}

}
