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

import java.awt.Panel;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;


public class CipherRSA {

    private String text;
    private String path;
    private String key1;
    private String key2;
    private boolean verifyMode;
    private String decryptionFinal="";

    public CipherRSA(String file, String keyRSA1, String keyRSA2, boolean ver) throws InvalidKeySpecException {
        this.verifyMode = ver;
        this.path = file;
        this.key1 = keyRSA1;
        this.key2=keyRSA2;        
        this.text = read(file);
    }

    private static String getHash(String txt, String hashType) {
        try {
           
            MessageDigest md = java.security.MessageDigest.getInstance(hashType);
            byte[] array = md.digest(txt.getBytes());
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < array.length; ++i) {
                sb.append(Integer.toHexString((array[i] & 0xFF) | 0x100).substring(1, 3));
            }
            
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }

    /* Retorna un hash MD5 a partir de un texto */
    public String md5() throws Exception {
        String h = CipherRSA.getHash(text, "MD5");       
        String a = path.substring(path.lastIndexOf('\\') + 1, path.length() - 4) + "_MD5.txt";
        write(a, text , encryptRSA(h,0));
        return "si";
    }

    /* Retorna un hash SHA1 a partir de un texto */
    public String sha1() throws Exception {
        String h = CipherRSA.getHash(text, "SHA1");
        String a = path.substring(path.lastIndexOf('\\') + 1, path.length() - 4) + "_SHA1.txt";
        return a;
    }

    public boolean verifyMD5() throws Exception {
        
        String[] a = text.split("///");
        String a1=a[0].substring(0, a[0].length()-1);
        System.out.println(text);
        System.out.println(a.length);
        boolean res=false;
        if (a.length == 2) {
            
            String[] beforeDecrypt=a1.substring(1, a1.length()).split("\n");    
            System.out.println(beforeDecrypt.length);
            if(beforeDecrypt.length!=1){
            for (int i=0;i<beforeDecrypt.length;i++) {
                 decryptionFinal = decryptionFinal+"\n"+decryptRSA(beforeDecrypt[i],1);
                }   
            res=decryptRSA(a[1],0).equals(CipherRSA.getHash(decryptionFinal.substring(1, decryptionFinal.length()),"MD5"));
            }else {
               String prueba=decryptRSA(a1,1);
               decryptionFinal=prueba;
               res=decryptRSA(a[1],0).equals(CipherRSA.getHash(prueba,"MD5"));
            }
          
          if(res){
                String name = path.substring(path.lastIndexOf('\\') + 1, path.length() - 4) + "_DE_MD5.txt";
                write(name,decryptionFinal,a[1]);
            }
          
          return res;
        }
      /* 
      
        boolean res=false;
        if (aMD5.length == 2) {
            System.out.println(text);
            
            String prueba=CipherRSA.getHash(aMD5[0].substring(0, aMD5[0].length()), "MD5");
            if(decryptRSA(aMD5[1],0).equals(prueba)){
            res=true;
            }        
            System.out.println(res);
            if(res){
                String name = path.substring(path.lastIndexOf('\\') + 1, path.length() - 4) + "_DE_MD5.txt";
                write(name,text);
            }
            return res;
        } else {
            JOptionPane.showMessageDialog(new Panel(), "Format incorrect!", "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }*/
      
        
        return res;
    }

    
   
   
    public boolean verifySHA1() throws Exception {
        System.out.println(text);
        String[] a = text.split("///");
        boolean res;
        
        if (a.length == 2) {
            //res = decryptRSA(a[1],1).equals(getHash(a[0], "SHA1"));
            res=true;
            if(res){
                String name = path.substring(path.lastIndexOf('\\') + 1, path.length() - 4) + "_DE_SHA1.txt";
                //write(name,text);
            }
            System.out.println(res);
            return res;
        } else {
            JOptionPane.showMessageDialog(new Panel(), "Format incorrect!", "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }
        private String decryptRSA(String cMessage,Integer modeOperador) throws NoSuchProviderException, InvalidKeySpecException {
        try {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
           if(modeOperador==0){
            File f = new File(key1);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
             byte[] keyBytes = new byte[(int) f.length()];
                dis.readFully(keyBytes);
                dis.close();
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey pub= kf.generatePublic(new X509EncodedKeySpec(keyBytes));
            
            System.out.println("todo correcto hasta aquí una vez2");
            cipher.init(Cipher.DECRYPT_MODE, pub);
            System.out.println("todo correcto hasta aquí una vez");
            
            return new String(cipher.doFinal(Base64.getDecoder().decode(cMessage)), "UTF-8");
            }else{
                File f=new File(key2);
                FileInputStream fis = new FileInputStream(f);
                DataInputStream dis = new DataInputStream(fis);         
                byte[] keyBytes = new byte[(int) f.length()];
                dis.readFully(keyBytes);
                dis.close();
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            
            PrivateKey pvt = kf.generatePrivate(spec);
                
                cipher.init(Cipher.DECRYPT_MODE, pvt);
                System.out.println("todo bien");
                return new String(cipher.doFinal(Base64.getDecoder().decode(cMessage.getBytes())), "UTF-8");
            }
            
            
            
           
        } catch (NoSuchAlgorithmException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el cifrador1", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (NoSuchPaddingException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el cifrador2", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el cifrador3", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (IllegalBlockSizeException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Seleccione archivos menores a 128 bytes", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (BadPaddingException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el cifrador4", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el archivo de la llave", "Error", JOptionPane.ERROR_MESSAGE);
        }  catch (InvalidKeyException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con las llaves, seleccione la indicada!", "Error", JOptionPane.ERROR_MESSAGE);
        }
        return null;
    }
    


    private String encryptRSA(String message, Integer modeOperador) throws Exception {
        try {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            if(modeOperador==0){
            File f = new File(key1);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] keyBytes = new byte[(int) f.length()];             
                dis.readFully(keyBytes);
                dis.close();
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
            
            PrivateKey pvt = kf.generatePrivate(spec);
            cipher.init(Cipher.ENCRYPT_MODE, pvt);
            return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8")));
            }else{
                File f=new File(key2);
                FileInputStream fis = new FileInputStream(f);
                DataInputStream dis = new DataInputStream(fis);         
                byte[] keyBytes = new byte[(int) f.length()];
                dis.readFully(keyBytes);
                dis.close();
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey pub= kf.generatePublic(new X509EncodedKeySpec(keyBytes));
                cipher.init(Cipher.ENCRYPT_MODE, pub);
                System.out.println("todo bien");
                return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8")));
            }
            
            
                
        } catch (NoSuchAlgorithmException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el cifrador 1", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (NoSuchPaddingException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el cifrador 2", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el cifrador 3", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (IllegalBlockSizeException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Seleccione archivos menores a 128 bytes", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (BadPaddingException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el cifrador 4", "Error", JOptionPane.ERROR_MESSAGE);
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con el archivo de la llave", "Error", JOptionPane.ERROR_MESSAGE);
        }catch (InvalidKeyException ex) {
            JOptionPane.showMessageDialog(new Panel(), "Error con las llaves, seleccione la indicada!", "Error", JOptionPane.ERROR_MESSAGE);
        }
        return "";
    }
    
    
    
    

    private void write(String file, String txt,String EncryptedHash) throws Exception {
        try {
            String cifradoFinal="";
             BufferedWriter writer = new BufferedWriter(new FileWriter(file));
            if (verifyMode) {
                writer.write(txt);
            } else {
                String[] aux=txt.split("\n");
                if(aux.length>1){
                for (int i=0;i<aux.length;i++) {
                    System.out.println(aux.length);
                    cifradoFinal = cifradoFinal+"\n"+encryptRSA(aux[i],1);
                }
                
                
                }else{
                cifradoFinal=encryptRSA(aux[0],1);
                System.out.println(cifradoFinal);
                }
                writer.write(cifradoFinal+"\n///"+EncryptedHash);
            }
            writer.close();
        } catch (IOException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public String read(String file) throws InvalidKeySpecException {
        String res = "";
        try {
            String line = null;
            BufferedReader bufferedReader = new BufferedReader(new FileReader(file));
            while ((line = bufferedReader.readLine()) != null) {
                    res += line + "\n";
            }
            bufferedReader.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CipherRSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println(res.length());
        return res.substring(0, res.length()-1);
    }
}

