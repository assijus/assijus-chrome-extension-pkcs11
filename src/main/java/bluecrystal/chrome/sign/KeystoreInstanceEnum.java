package bluecrystal.chrome.sign;

import com.google.gson.annotations.SerializedName;

public enum KeystoreInstanceEnum {
	PKCS11(0,"Token/Smartcard","e-CPF armazenado em cartão ou token","A3"), 
	PKCS12(2,"Arquivo PKCS12","e-CPF armazenado em seu computador (*.p12)","A1"), 
	APPLE(3,"Armazenamento no dispositivo Mac OS","e-CPF instalado em seu computador Mac OS","A1");
	
	private final Integer id;
	private final String keystoreMedia;
	private final String keystoreDescription;
	private final String keystoreCertificateType;
	
	KeystoreInstanceEnum(int id, String keystoreMedia, String keystoreDescription, String keystoreCertificateType) {
		this.id = id;
		this.keystoreMedia = keystoreMedia;
		this.keystoreDescription = keystoreDescription;
		this.keystoreCertificateType = keystoreCertificateType;
	}

	public Integer getId() {
		return id;
	}

	public String getKeystoreMedia() {
		return keystoreMedia;
	}

	public String getKeystoreCertificateType() {
		return keystoreCertificateType;
	}

	public String getKeystoreDescription() {
		return keystoreDescription;
	}
}
