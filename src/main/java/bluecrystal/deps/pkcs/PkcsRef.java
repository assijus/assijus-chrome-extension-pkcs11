package bluecrystal.deps.pkcs;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Provider;

public class PkcsRef {

	private String PKCSLibrary = null;
	private String configString = null;
	private ByteArrayInputStream configStream = null;
	private KeyStore keyStore = null;
	private Provider pkcsProvider = null;

	public String getPKCSLibrary() {
		return PKCSLibrary;
	}

	public void setPKCSLibrary(String pKCS11Library) {
		PKCSLibrary = pKCS11Library;
	}

	public String getConfigString() {
		return configString;
	}

	public void setConfigString(String configString) {
		this.configString = configString;
	}

	public ByteArrayInputStream getConfigStream() {
		return configStream;
	}

	public void setConfigStream(ByteArrayInputStream configStream) {
		this.configStream = configStream;
	}

	public KeyStore getKeyStore() {
		return keyStore;
	}

	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}

	public Provider getPkcsProvider() {
		return pkcsProvider;
	}

	public void setPkcsProvider(Provider pkcsProvider) {
		this.pkcsProvider = pkcsProvider;
	}

}
