package Controller;

import net.i2p.crypto.CertUtil;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;
import java.util.Set;

public class CertificateController{


    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";



    public void createUserCertificate(String username, String password) throws Exception{
        // Add the BouncyCastle Provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Initialize a new KeyPair generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);

        // Setup start date to yesterday and end date for 60 days validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.DATE, 183);
        Date endDate = calendar.getTime();


        File privateKeyFile = new File(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"priv"+File.separator+"caDER.key");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey priv = keyFactory.generatePrivate(privateKeySpec);
        File CA = new File( System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"ca.crt");


        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream (CA);
        X509Certificate CAcer = (X509Certificate) fact.generateCertificate(is);
        PublicKey pub = CAcer.getPublicKey();
        is.close();
        KeyPair CAkey = new KeyPair(pub,priv);
        X500Name dirName = new X500Name(CAcer.getSubjectDN().getName());

        File serialNumber = new File(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"serial.txt");
        Scanner scanner = new Scanner(serialNumber);
        // getting serial number from file
        BigInteger number = new BigInteger(scanner.nextLine());
        BigInteger tmp = new BigInteger("1");
        // setting value for next serial number +1
        BigInteger value = number.add(tmp);
        scanner.close();
        //printing next serial number into file
        PrintStream print = new PrintStream(serialNumber);
        print.println(value);
        print.close();


        X500Name issuedCertSubject = new X500Name("CN="+username);
        KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrContentSigner = csrBuilder.build(CAkey.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        // Use the Signed KeyPair and CSR to generate an issued Certificate

        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(dirName, number, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(CAcer));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        // Add intended key usage extension if needed
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
        //issuedCertBuilder.addExtension(Extension.cRLDistributionPoints,false,new CRLDistPoint());

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

        // Verify the issued cert signature against the root (issuer) cert
        issuedCert.verify(CAcer.getPublicKey(), BC_PROVIDER);

        exportKeyPairToKeystoreFile(issuedCertKeyPair,  issuedCert, username, username+".pfx", "PKCS12",password);

    }


    static void exportKeyPairToKeystoreFile(KeyPair keyPair, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }

    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }
    public void giveUserCert(String username,String password) throws Exception{
        Process process;
        String command ="openssl pkcs12 -in .\\root\\certs\\certs\\"+username+".pfx -nokeys -clcerts -out C:\\Users\\admin\\Desktop\\KriptoCerts\\"+username+
                        ".crt -passin pass:"+password;
        Runtime runtime = Runtime.getRuntime();
        process = runtime.exec(command);
    }
    public void revokeCert(X509Certificate usercert,FileInputStream inputCRL)throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(
                new BouncyCastleProvider());
        Calendar calendar = Calendar.getInstance(); // Get a Calendar instance
        calendar.add(Calendar.DAY_OF_YEAR, 7); // Add 7 days to the current date
        Date date = calendar.getTime(); // Convert Calendar to Date
        File privateKeyFile = new File(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"priv"+File.separator+"caDER.key");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey priv = keyFactory.generatePrivate(privateKeySpec);

        //loading existing CRL

        ASN1InputStream asn1Stream = new ASN1InputStream(inputCRL);
        X509CRLHolder crlHolder = new X509CRLHolder(asn1Stream);
        asn1Stream.close();
        X509CRL existingCRL = new JcaX509CRLConverter().getCRL(crlHolder);
        System.out.println(existingCRL);
        Set<? extends java.security.cert.X509CRLEntry> revokedCertificates = existingCRL.getRevokedCertificates();

        // Create a new CRL builder
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crlHolder.getIssuer(), new Date());
        // Create a new CRL entry for the revoked certificate
        X509CertificateHolder revokedCertificate = new X509CertificateHolder(org.bouncycastle.asn1.x509.Certificate.getInstance(usercert.getEncoded()));
        for (java.security.cert.X509CRLEntry entry : revokedCertificates) {
            crlBuilder.addCRLEntry(entry.getSerialNumber(),entry.getRevocationDate(),entry.getRevocationReason().ordinal());
        }
        crlBuilder.addCRLEntry(revokedCertificate.getSerialNumber(), new Date(), CRLReason.certificateHold);
        // Sign the new CRL with the CA's private key
        X509CRLHolder newCRL = crlBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(priv));
        X509CRL CRLNew = new JcaX509CRLConverter().getCRL(newCRL);


        System.out.println(CRLNew);

        //saving new crl
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ASN1OutputStream asn1OutputStream = ASN1OutputStream.create(byteArrayOutputStream);
        CertificateList certificateList = CertificateList.getInstance(CRLNew.getEncoded());

        // Write the X509CRL to the output stream in DER format
        asn1OutputStream.writeObject(certificateList);

        // Print out the DER-encoded data
        byte[] derData = byteArrayOutputStream.toByteArray();
        for (int i = 0; i < derData.length; i++) {
            System.out.printf("%02X", derData[i]);
        }

        // Optionally, write the DER-encoded data to a file
        OutputStream outputStream = new FileOutputStream(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"crl"+File.separator+"CRL1.crl");
        outputStream.write(derData);
        outputStream.close();
    }

    public void unrevokeCert(X509Certificate userCert)throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(
                new BouncyCastleProvider());

        File privateKeyFile = new File(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"priv"+File.separator+"caDER.key");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey priv = keyFactory.generatePrivate(privateKeySpec);

        File crlFile2 = new File(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"crl"+File.separator+"CRL1.crl");
        DataInputStream dataStream = new DataInputStream(new FileInputStream(crlFile2));
        X509CRL CRL2 = CertUtil.loadCRL(dataStream);
        DataInputStream dataStream2 = new DataInputStream(new FileInputStream(crlFile2));

        X509CRLHolder existingCRL = new X509CRLHolder(dataStream2);

        // get the revoked certificate entry to be unrevoked

// Create a new CRL with the revoked certificate entry removed
                X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(existingCRL.getIssuer(), CRL2.getThisUpdate());
        CRL2.getRevokedCertificates().stream()
                .filter(entry -> !entry.getSerialNumber().equals(userCert.getSerialNumber()))

                .forEach(entry -> crlBuilder.addCRLEntry(
                        entry.getSerialNumber(),
                        CRL2.getThisUpdate(),
                        CRLReason.certificateHold
                ));

        X509CRLHolder unrevokedCrl = crlBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(priv));
        X509CRL CRLNew = new JcaX509CRLConverter().getCRL(unrevokedCrl);
        System.out.println(CRLNew);
// unrevokedCrl now contains the CRL with the specified certificate entry unrevoked
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ASN1OutputStream asn1OutputStream = ASN1OutputStream.create(byteArrayOutputStream);
        CertificateList certificateList = CertificateList.getInstance(CRLNew.getEncoded());

        // Write the X509CRL to the output stream in DER format
        asn1OutputStream.writeObject(certificateList);

        // Print out the DER-encoded data
        byte[] derData = byteArrayOutputStream.toByteArray();
        for (int i = 0; i < derData.length; i++) {
            System.out.printf("%02X", derData[i]);
        }

        // Optionally, write the DER-encoded data to a file
        OutputStream outputStream = new FileOutputStream(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"crl"+File.separator+"CRL1.crl");
        outputStream.write(derData);
        outputStream.close();
        }



    public void exportUpdatedCRL(X509CRL CRL)throws Exception{
        byte[] buf = CRL.getEncoded();
        File fileCRL =  new File(System.getProperty("user.dir")+File.separator+"root"+File.separator+"certs"+File.separator+"crl"+File.separator+"CRL.crl");
        FileOutputStream os = new FileOutputStream(fileCRL);
        CertUtil.exportCRL(CRL,os);
        os.flush();
        os.close();

    }
    public static Date calculateDate(int hoursInFuture)
    {
        long secs = System.currentTimeMillis() / 1000;


        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }
}
