/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hashrsa;

/**
 *
 * @author Itzel A
 */
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerateKeys {
	
	private KeyPairGenerator generadorLlaves;
	private KeyPair llavesAsimetricas;
	private PrivateKey llavePrivada;
	private PublicKey llavePublica;
	
	public GenerateKeys(int keySize) throws NoSuchAlgorithmException {
		this.generadorLlaves = KeyPairGenerator.getInstance("RSA");
		this.generadorLlaves.initialize(keySize);
	}
	
	public void createKeys() {
		this.llavesAsimetricas = this.generadorLlaves.generateKeyPair();
		this.llavePrivada = llavesAsimetricas.getPrivate();
		this.llavePublica = llavesAsimetricas.getPublic();
	}
	
	public void crearArchivosLLave(String path, byte[] llave) throws IOException {
		File f = new File(path);
		f.getParentFile().mkdirs();
		
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(llave);
		fos.flush();
		fos.close();
	}
	
    public static void main( String[] args ) throws NoSuchAlgorithmException{
    	GenerateKeys gk;
    	try {
	    	gk = new GenerateKeys(1024);
			gk.createKeys();
			//encoded.- Entre UNICODE y otros tipos de characterEnconding
			gk.crearArchivosLLave("keyGenerate/publicKey.txt", gk.getLlavePublica().getEncoded());
			gk.crearArchivosLLave("keyGenerate/privateKey.txt", gk.getLlavePrivada().getEncoded());
			System.out.println("Llaves generadas");
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	
	}
    
	public PrivateKey getLlavePrivada() {
		return llavePrivada;
	}

	public void setLlavePrivada(PrivateKey llavePrivada) {
		this.llavePrivada = llavePrivada;
	}

	public PublicKey getLlavePublica() {
		return llavePublica;
	}

	public void setLlavePublica(PublicKey llavePublica) {
		this.llavePublica = llavePublica;
	}
    
    
}
