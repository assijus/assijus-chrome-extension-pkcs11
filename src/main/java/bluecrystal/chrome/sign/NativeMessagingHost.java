package bluecrystal.chrome.sign;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import bluecrystal.deps.pkcs.util.Base64Coder;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class NativeMessagingHost {
	// static {
	// System.setProperty(org.slf4j.impl.SimpleLogger.DEFAULT_LOG_LEVEL_KEY,
	// "DEBUG");
	// System.setProperty(org.slf4j.impl.SimpleLogger.LOG_FILE_KEY,
	// "~/Library/Assijus/log.txt");
	// }
	static final Logger LOG = LoggerFactory.getLogger(NativeMessagingHost.class);

	static class CurrentCert {
		String alias = null;
		String certificate = null;
		String subject = null;
		String userPIN = null;
		KeystoreInstanceEnum keystoreInstance = KeystoreInstanceEnum.PKCS11; //default 
		int keySize = 0;
	}

	public static CurrentCert current = new CurrentCert();

	private static PkcsWrapper pkcs = null;

	public static void main(String[] args) throws Exception {
		// TODO: esse init deve ser executado pelo GET de um método chamado
		// /init
		pkcs = new PkcsWrapper("aetpkss1.dll;eTPKCS11.dll;asepkcs.dll;libaetpkss.dylib;libeTPkcs11.dylib",
				"/usr/local/lib");
		for (;;) {

			byte[] bytes;
			try {
				bytes = read(4);
			} catch (IndexOutOfBoundsException iobe) {
				break;
			}
			int requestLength = getInt(bytes);

			if (requestLength == 0)
				break;

			byte[] request = read(requestLength);
			String sReq = new String(request, StandardCharsets.UTF_8);
			LOG.debug("mensagem recebida:" + sReq);
			String sResp = run(sReq);
			LOG.debug("mensagem enviada: " + sResp);
			byte[] response = sResp.getBytes(StandardCharsets.UTF_8);
			write(response);
		}
	}

	private static int getInt(byte[] bytes) {
		return (bytes[3] << 24) & 0xff000000 | (bytes[2] << 16) & 0x00ff0000 | (bytes[1] << 8) & 0x0000ff00
				| (bytes[0] << 0) & 0x000000ff;
	}

	private static byte[] getBytes(int length) {
		byte[] bytes = new byte[4];
		bytes[0] = (byte) (length & 0xFF);
		bytes[1] = (byte) ((length >> 8) & 0xFF);
		bytes[2] = (byte) ((length >> 16) & 0xFF);
		bytes[3] = (byte) ((length >> 24) & 0xFF);
		return bytes;
	}

	private static byte[] read(int count) throws IOException {
		byte[] bytes = new byte[count];
		int off = 0;
		int len = count;
		while (len > 0) {
			int read = System.in.read(bytes, off, len);
			off += read;
			len -= read;
		}
		return bytes;
	}

	public static void write(byte[] bytes) throws IOException {
		int l = bytes.length;
		System.out.write(getBytes(l));
		System.out.write(bytes, 0, bytes.length);
	}

	final static Gson gson = new Gson();

	private static String run(String msg) {
		String jsonOut = "";
		try {
			GenericRequest genericrequest = gson.fromJson(msg, GenericRequest.class);

			if (genericrequest.url.endsWith("/test"))
				jsonOut = test();
			else if (genericrequest.url.endsWith("/currentcert"))
				jsonOut = currentcert();
			else if (genericrequest.url.endsWith("/cert"))
				jsonOut = cert(genericrequest.data);
			else if (genericrequest.url.endsWith("/token"))
				jsonOut = token(genericrequest.data);
			else if (genericrequest.url.endsWith("/sign"))
				jsonOut = sign(genericrequest.data);
			else if (genericrequest.url.endsWith("/clearcurrentcert"))
				jsonOut = clearCurrentCertificateRequest(genericrequest.data);
			else
				return "{\"success\":false,\"data\":{\"errormsg\":\"Error 404: file not found\"}}";
			return "{\"success\":true,\"data\":" + jsonOut + "}";
		} catch (Exception ex) {
			// LOG.error("Mensagem não pode ser processada", ex);
			String message = ex.getMessage();
			if (message != null && message.startsWith("O conjunto de chaves não"))
				message = "Não localizamos nenhum Token válido no computador. Por favor, verifique se foi corretamente inserido.";
			return "{\"success\":false,\"status\":500,\"data\":{\"errormsg\":\"" + jsonStringSafe(message) + "\"}}";
		}
	}

	private static String clearCurrentCertificateRequest(RequestData data) {
		GenericResponse response = new GenericResponse();
		clearCurrentCertificate();
		
		response.errormsg = "OK";
		return gson.toJson(response);
	}

	private static String test() {
		TestResponse testresponse = new TestResponse();
		testresponse.provider = "Assijus Signer Extension - PKCS";
		testresponse.version = "2.0.0-PKCS";
		testresponse.status = "OK";
		testresponse.clearCurrentCertificateEnabled = true;
		
		List<KeystoreInstanceEnum> list = new ArrayList<KeystoreInstanceEnum>();
		list.add(KeystoreInstanceEnum.PKCS11);
		list.add(KeystoreInstanceEnum.APPLE);
		testresponse.keystoreSupported = list;
		
		GsonBuilder builder = new GsonBuilder();
		builder.registerTypeAdapterFactory(new EnumAdapterFactory());
		Gson gson = builder.create();
		
		return gson.toJson(testresponse);
	}

	private static String currentcert() {
		try {
			CertificateResponse certificateresponse = new CertificateResponse();
			certificateresponse.subject = current.subject;
			certificateresponse.certificate = current.certificate;
			// if (sorn(certificateresponse.subject) != null) {
			// certificateresponse.certificate = getCertificate(
			// "Assinatura Digital",
			// "Escolha o certificado que será utilizado na assinatura.",
			// certificateresponse.subject, "");
			// certificateresponse.subject = current.subject;
			// }

			if (sorn(certificateresponse.subject) == null) {
				certificateresponse.subject = null;
				certificateresponse.errormsg = "Nenhum certificado ativo no momento.";
			}

			return gson.toJson(certificateresponse);
		} catch (Exception ex) {
			clearCurrentCertificate();
			throw ex;
		}
	}

	private static String cert(RequestData req) throws Exception {
		try {
			current.userPIN = req.userPIN;
			
			if (req.keystore != null)
				current.keystoreInstance = KeystoreInstanceEnum.valueOf(req.keystore);

			if (!current.keystoreInstance.equals(KeystoreInstanceEnum.APPLE)) {
				if (current.userPIN == null) {
					throw new Exception("PIN não informado");
				}
			}
			
			String subjectRegEx = "ICP-Brasil";

			if (req != null && sorn(req.subject) != null) {
				subjectRegEx = req.subject;
			}
			
			if (current.keystoreInstance.equals(KeystoreInstanceEnum.APPLE)) {
				pkcs.setStore(PkcsWrapper.STORE_APPLE);
			} else {
				pkcs.setStore(PkcsWrapper.STORE_PKCS11);
			}
			
			CertificateResponse certificateresponse = new CertificateResponse();

			String json = listCerts(pkcs);

			Type listType = new TypeToken<List<AliasAndSubject>>() {
			}.getType();
			List<AliasAndSubject> list = new Gson().fromJson(json, listType);

			List<AliasAndSubject> filteredlist = new ArrayList<>();
			for (AliasAndSubject aas : list) {
				if (aas.subject != null && aas.subject.equals(subjectRegEx)) {
					filteredlist.add(aas);
					break;
				}
			}
			if (filteredlist.size() == 0) {
				for (AliasAndSubject aas : list) {
					if (aas.subject != null && aas.subject.contains(subjectRegEx))
						filteredlist.add(aas);
				}
			}

			if (filteredlist.size() == 0) {
				certificateresponse.errormsg = "Nenhum certificado encontrado.";
			} else if (filteredlist.size() == 1) {
				current.alias = filteredlist.get(0).alias;
				current.subject = filteredlist.get(0).subject;
				current.certificate = pkcs.getCert(current.alias);
				current.keySize = pkcs.getKeySize(current.alias);
				certificateresponse.certificate = current.certificate;
				certificateresponse.subject = current.subject;
			} else if (filteredlist.size() > 1) {
				certificateresponse.list = filteredlist;
			}
			return gson.toJson(certificateresponse);
		} catch (Exception ex) {
			clearCurrentCertificate();
			throw ex;
		}

	}

	private static String token(RequestData req) throws Exception {
		try {
			if (!current.keystoreInstance.equals(KeystoreInstanceEnum.APPLE)) {
				if (current.userPIN == null) {
					throw new Exception("PIN não informado");
				}
			}

			if (req.subject != null) {
				String s = getCertificateBySubject(req.subject);
			}

			if (!req.token.startsWith("TOKEN-"))
				throw new Exception("Token should start with TOKEN-.");

			if (req.token.length() > 128 || req.token.length() < 16)
				throw new Exception("Token too long or too shor.");

			byte[] datetime = req.token.getBytes(StandardCharsets.UTF_8);
			String payloadAsString = new String(Base64Coder.encode(datetime));

			TokenResponse tokenresponse = new TokenResponse();
			for (int i = 0;; i++) {
				try {
					LOG.debug("tentanto gerar token.");
					int alg = 99;

					tokenresponse.sign = pcksSign(pkcs, alg, payloadAsString);
					break;
				} catch (Exception e) {
					if (i > 10)
						throw e;
					if (!"Private keys must be instance of RSAPrivate(Crt)Key or have PKCS#8 encoding"
							.equals(e.getMessage())) {
						throw e;
					}
				}
			}
			tokenresponse.subject = current.subject;
			tokenresponse.token = req.token;

			return gson.toJson(tokenresponse);
		} catch (Exception ex) {
			clearCurrentCertificate();
			throw ex;
		}
	}

	private static String sign(RequestData req) throws Exception {
		try {
			if (!current.keystoreInstance.equals(KeystoreInstanceEnum.APPLE)) {
				if (current.userPIN == null) {
					throw new Exception("PIN não informado");
				}
			}

			if (req.subject == null) {
				String s = getCertificateBySubject(req.subject);
			}

			int keySize = current.keySize;
			SignResponse signresponse = new SignResponse();
			for (int i = 0;; i++) {
				try {
					LOG.debug("tentanto assinar.");
					int alg;
					if ("PKCS7".equals(req.policy))
						alg = 99;
					else if (keySize < 2048)
						alg = 0;
					else
						alg = 2;
					signresponse.sign = pcksSign(pkcs, alg, req.payload);
					break;
				} catch (Exception e) {
					if (i > 10)
						throw e;
					if (!"Private keys must be instance of RSAPrivate(Crt)Key or have PKCS#8 encoding"
							.equals(e.getMessage())) {
						throw e;
					}
				}
			}

			signresponse.subject = current.subject;

			return gson.toJson(signresponse);
		} catch (Exception ex) {
			clearCurrentCertificate();
			throw ex;
		}

	}

	private static void clearCurrentCertificate() {
		current.alias = null;
		current.certificate = null;
		current.subject = null;
		current.userPIN = null;
		current.keystoreInstance = KeystoreInstanceEnum.PKCS11;
		current.keySize = 0;
	}

	private static String getCertificateBySubject(String sub) {

		return null;
	}

	public static String listCerts(PkcsWrapper pWrap) throws Exception {
		try {
			pWrap.setUserPIN(current.userPIN);
			pWrap.loadKeyStore();
			pWrap.setUserPIN(current.userPIN);
			pWrap.refreshCerts();

			String ret = "";
			String json = pWrap.loadCertsJson();
			return json;
		} catch (Exception e) {
			LOG.error("can't load que keystore", e);
			if (e instanceof IOException) {
				if (e.getCause() != null && e.getCause() instanceof FailedLoginException
						|| e.getCause() instanceof LoginException) {
					if (e.getCause().getCause() != null && e.getCause().getCause() instanceof PKCS11Exception) {
						throw (PKCS11Exception) e.getCause().getCause();
					}
				}
			}
			throw new Exception("Não foi possível acessar o token", e);
		}
	}

	public static String pcksSign(PkcsWrapper pcks, int alg, String payload) throws Exception {
		pcks.setUserPIN(current.userPIN);
		pcks.setCertAlias(current.alias);
		pcks.setOrig(payload);
		pcks.setAlg(alg);
		pcks.sign();
		String ret = pcks.getResult();
		return ret;
	}

	private static String jsonStringSafe(String s) {
		if (s == null)
			return "null";
		s = s.replace("\r", " ");
		s = s.replace("\n", " ");
		return s;
	}

	private static String sorn(String s) {
		if (s == null)
			return null;
		if (s.trim().length() == 0)
			return null;
		return s;
	}

	private static class AliasAndSubject {
		String alias;
		String subject;
	}

	private static class RequestData {
		String certificate;
		String subject;
		String payload;
		String policy;
		String code;
		String token;
		String userPIN;
		String keystore;
	}

	private static class GenericRequest {
		String url;
		RequestData data;
	}

	private static class GenericResponse {
		String errormsg;
	}

	private static class TestResponse {
		String provider;
		String version;
		String status;
		Boolean clearCurrentCertificateEnabled;
		String errormsg;
		List<KeystoreInstanceEnum> keystoreSupported;
	}

	private static class CertificateResponse {
		String certificate;
		String subject;
		String errormsg;
		List<AliasAndSubject> list;
	}

	private static class SignResponse {
		String sign;
		String signkey;
		String subject;
		String errormsg;
	}

	private static class TokenResponse {
		String sign;
		String token;
		String subject;
		String errormsg;
	}

}
