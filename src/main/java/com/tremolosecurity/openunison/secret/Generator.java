package com.tremolosecurity.openunison.secret;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecHostsInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecHostsInnerAnnotationsInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecHostsInnerNamesInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreKeyPairsKeysInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreKeyPairsKeysInnerCreateData;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreKeyPairsKeysInnerCreateDataSecretInfo;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreTrustedCertificatesInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreKeyPairsKeysInner.ImportIntoKsEnum;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.obj.CertificateData;
import com.tremolosecurity.openunison.obj.WsResponse;
import com.tremolosecurity.openunison.obj.X509Data;
import com.tremolosecurity.openunison.util.CertUtils;
import com.tremolosecurity.openunison.util.NetUtils;

public class Generator {
    OpenUnison ou;
    String name;
    String namespace;
    ClusterConnection cluster;
    Map<String,String> props;

    KeyStore ouKs;

    public Map<String, String> getProps() {
        return props;
    }

    public Generator() {
        this.props = new HashMap<String,String>();
    }

    public void load(OpenUnison ou,ClusterConnection cluster,String namespace,String name) throws Exception {
        this.ou = ou;
        this.namespace = namespace;
        this.name = name;
        this.cluster = cluster;
        this.loadPropertiesFromCrd();
        this.loadPropertiesFromSecret();
        this.generateKeyStore();
    }

    private void loadPropertiesFromCrd() throws Exception {
        for (OpenUnisonSpecHostsInnerAnnotationsInner data : ou.getSpec().getNonSecretData()) {
            props.put(data.getName(), data.getValue());
        }

        this.props.put("K8S_SELF_LINK", new URL(cluster.getWatchUrl()).getPath() + "/" + this.name);

        for (OpenUnisonSpecHostsInner host : ou.getSpec().getHosts()) {
            for (OpenUnisonSpecHostsInnerNamesInner name : host.getNames()) {
                props.put(name.getEnvVar(), name.getName());
            }
        }

        //String myIp = NetUtils.whatsMyIP();
        //String mask = myIp.substring(0,myIp.indexOf("."));
        this.props.put("OU_QUARTZ_MASK", "");
    

    }

    private void loadPropertiesFromSecret() throws Exception {
        WsResponse resp = this.cluster.getSecret(this.namespace, this.ou.getSpec().getSourceSecret());
        
        if (resp.getResult() >= 200 && resp.getResult() < 300) {
            JSONObject data = (JSONObject) resp.getBody().get("data");
            if (data != null) {
                for (String secretProp : ou.getSpec().getSecretData()) {
                    String b64val = (String) data.get(secretProp);
                    if (b64val != null) {
                        String val = new String(Base64.getDecoder().decode(b64val));
                        this.props.put(secretProp, val);
                    }
                }
            }
            
        } else {
            throw new Exception("Unexpected error code trying to retrive the source secret " + this.ou.getSpec().getSourceSecret() + " from ns " + this.namespace + " / " + resp.getResult() + " / " + resp.getBody());
        }
    }

    private void generateKeyStore() throws Exception {
        String ksPassword = this.props.get("unisonKeystorePassword");
        this.ouKs = KeyStore.getInstance("PKCS12");
        ouKs.load(null, ksPassword.toCharArray());

        CertUtils.importCertificate(ouKs, ksPassword, "k8s-api-host", Files.readString(Path.of(cluster.getPathToCert())));

        if (this.ou.getSpec().getKeyStore() != null && this.ou.getSpec().getKeyStore().getTrustedCertificates() != null) {
            for (OpenUnisonSpecKeyStoreTrustedCertificatesInner trustedCert : this.ou.getSpec().getKeyStore().getTrustedCertificates()) {
                CertUtils.importCertificate(ouKs,ksPassword,trustedCert.getName(),trustedCert.getPemData());
            }
        }

        if (this.ou.getSpec().getKeyStore() != null && this.ou.getSpec().getKeyStore().getKeyPairs() != null && this.ou.getSpec().getKeyStore().getKeyPairs() != null) {
            for (OpenUnisonSpecKeyStoreKeyPairsKeysInner keySpec : this.ou.getSpec().getKeyStore().getKeyPairs().getKeys() ) {
                this.processKeyPair(keySpec,ksPassword);
            }
        }

    }

    private void processKeyPair(OpenUnisonSpecKeyStoreKeyPairsKeysInner keySpec,String ksPassword) throws Exception {
        boolean secretExists = false;
        System.out.println("Processing key : " + keySpec.getName());
        // if no Secret info is specified, create a standard Kubernetes TLS Secret
        if (keySpec.getCreateData().getSecretInfo() == null) {
            keySpec.getCreateData().setSecretInfo(
                new OpenUnisonSpecKeyStoreKeyPairsKeysInnerCreateDataSecretInfo()
                .typeOfSecret("kubernetes.io/tls")
                .certName("tls.crt")
                .keyName("tls.key")
            );
        }

        String targetNs = this.namespace;
        if (keySpec.getCreateData().getTargetNamespace() != null && ! keySpec.getCreateData().getTargetNamespace().isBlank()) {
            targetNs = keySpec.getCreateData().getTargetNamespace();
        }

        System.out.println("Secret namespace : " + targetNs);

        String secretName = keySpec.getName();
        if (keySpec.getTlsSecretName() != null && !keySpec.getTlsSecretName().isBlank()) {
            secretName = keySpec.getTlsSecretName();
        } 

        System.out.println("Secret name : " + secretName);

        // check if the secret already exist
        WsResponse resp = this.cluster.getSecret(targetNs, secretName);

        if (resp.getResult() == 200) {
            JSONObject data = (JSONObject) resp.getBody().get("data");
            JSONObject metadata = (JSONObject) resp.getBody().get("metadata");
            JSONObject labels = (JSONObject) metadata.get("labels");
            if (labels == null) {
                labels = new JSONObject();
            }

            if (data == null) {
                data = new JSONObject();
            }



            System.out.println("Secret exists");
            if (keySpec.getReplaceIfExists() == null || ! keySpec.getReplaceIfExists()) {
                System.out.println("Adding existing secret that should never be replaced if exists to keystore");
                if (keySpec.getImportIntoKs() == null || keySpec.getImportIntoKs() == ImportIntoKsEnum.KEYPAIR) {
                    System.out.println("Storing keypair into keystore");
                    CertUtils.importKeyPairAndCert(ouKs,ksPassword,keySpec.getName(),(String)data.get(keySpec.getCreateData().getSecretInfo().getKeyName()),(String)data.get(keySpec.getCreateData().getSecretInfo().getCertName()));
                } else if (keySpec.getImportIntoKs() == ImportIntoKsEnum.CERTIFICATE) {
                    System.out.println("Storing just the certificate for the existing Secret");
                    CertUtils.importCertificate(ouKs,ksPassword,keySpec.getName(),new java.lang.String(java.util.Base64.getDecoder().decode((String)data.get(keySpec.getCreateData().getSecretInfo().getCertName()))));
                } else {
                    System.out.println("Not storing certificate or keypair");
                }

                return;
                
            } else {
                if (labels.get("tremolo_operator_created") != null) {
                    System.out.println("Secret exists that can be replaced");
                    if (keySpec.getImportIntoKs() == null || keySpec.getImportIntoKs() == ImportIntoKsEnum.KEYPAIR) {
                        System.out.println("Storing keypair into keystore");
                        CertUtils.importKeyPairAndCert(ouKs,ksPassword,keySpec.getName(),(String)data.get(keySpec.getCreateData().getSecretInfo().getKeyName()),(String)data.get(keySpec.getCreateData().getSecretInfo().getCertName()));
                    } else if (keySpec.getImportIntoKs() == ImportIntoKsEnum.CERTIFICATE) {
                        System.out.println("Storing just the certificate for the existing Secret");
                        CertUtils.importCertificate(ouKs,ksPassword,keySpec.getName(),new java.lang.String(java.util.Base64.getDecoder().decode((String)data.get(keySpec.getCreateData().getSecretInfo().getCertName()))));
                    } else {
                        System.out.println("Not storing certificate or keypair");
                    }
                    return;
                }

                


            }
            
            secretExists = true;
            
        } 

        System.out.println("Creating keypair");

        CertificateData certData = new CertificateData();
        
        for (OpenUnisonSpecHostsInnerAnnotationsInner nvp : this.ou.getSpec().getKeyStore().getKeyPairs().getCreateKeypairTemplate()) {
            if (nvp.getName().equalsIgnoreCase("o")) {
                certData.setO(nvp.getValue());
            } else if (nvp.getName().equalsIgnoreCase("c")) {
                certData.setC(nvp.getValue());
            } else if (nvp.getName().equalsIgnoreCase("l")) {
                certData.setL(nvp.getValue());
            } else if (nvp.getName().equalsIgnoreCase("ou")) {
                certData.setOu(nvp.getValue());
            } 
        }

        certData.setCaCert(keySpec.getCreateData().getCaCert());
        certData.setSize(keySpec.getCreateData().getKeySize());

        String serverName = keySpec.getCreateData().getServerName();
        certData.setServerName(serverName);

        if (keySpec.getCreateData().getSubjectAlternativeNames() != null) {
            certData.setSubjectAlternativeNames(new LinkedHashMap());
            certData.getSubjectAlternativeNames().addAll(keySpec.getCreateData().getSubjectAlternativeNames());
        }

        X509Data x509data = CertUtils.createCertificate(certData);
        
        JSONObject secretToCreate = new JSONObject();
        secretToCreate.put("apiVersion", "v1");
        secretToCreate.put("kind","Secret");
        secretToCreate.put("type",keySpec.getCreateData().getSecretInfo().getTypeOfSecret());
        JSONObject metadata = new JSONObject();
        secretToCreate.put("metadata",metadata);
        metadata.put("name", secretName);
        metadata.put("namespace",targetNs);
        JSONObject labels = new JSONObject();
        metadata.put("labels",labels);
        labels.put("tremolo_operator_created", "true");
        labels.put("operated-by","openunison-operator");
        labels.put("app.kubernetes.io/managed-by","openunison-operator");
        JSONObject data = new JSONObject();
        secretToCreate.put("data", data);

        data.put(keySpec.getCreateData().getSecretInfo().getCertName(), java.util.Base64.getEncoder().encodeToString(CertUtils.exportCert(x509data.getCertificate()).getBytes("UTF-8")));
        data.put(keySpec.getCreateData().getSecretInfo().getKeyName(),java.util.Base64.getEncoder().encodeToString(CertUtils.exportKey(x509data.getKeyData().getPrivate()).getBytes("UTF-8")));
        
    
        if (secretExists) {
            String uri = "/api/v1/namespaces/" + targetNs + "/secrets/" + secretName;
            System.out.println("Deleting existing Secret : " + uri);
            this.cluster.delete(uri);
        }

        System.out.println("Creating new Secret");
        this.cluster.post("/api/v1/namespaces/" + targetNs + "/secrets",secretToCreate.toString());

        if (keySpec.getCreateData().getDeletePodsLabels() != null && ! keySpec.getCreateData().getDeletePodsLabels().isEmpty()) {
            boolean first = true;
            String params = "";
            for (String label : keySpec.getCreateData().getDeletePodsLabels()) {
                if (! first) {
                    params += "&";
                    
                } else {
                    first = false;
                }

                params += "labelSelector=" + URLEncoder.encode(label,"UTF-8");
            }   

            String uriToDelete = "/api/v1/namespaces/" + targetNs + "/pods?" + params;
            System.out.println("Deleting pods - " + uriToDelete);
            cluster.delete(uriToDelete);
        }

        if (keySpec.getImportIntoKs() == null || keySpec.getImportIntoKs() == null || keySpec.getImportIntoKs() == ImportIntoKsEnum.KEYPAIR) {
            System.out.println("Storing the keypair into the keystore");
            CertUtils.saveX509ToKeystore(ouKs, ksPassword, keySpec.getName(), x509data);
        } else if (keySpec.getImportIntoKs() == ImportIntoKsEnum.CERTIFICATE) {
            System.out.println("Importing the certificate into the keystore");
            CertUtils.importCertificate(ouKs, ksPassword, keySpec.getName(), x509data.getCertificate());
        } else {
            System.out.println("Not storing at all");
        }

        System.out.println(String.format("Key %s finished",keySpec.getName()));
    
    
    }

    
    
    
}
