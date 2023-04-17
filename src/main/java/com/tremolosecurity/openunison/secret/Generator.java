package com.tremolosecurity.openunison.secret;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Certificate;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.joda.time.DateTime;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.google.gson.GsonBuilder;
import com.tremolosecurity.openunison.JSON;
import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecHostsInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecHostsInnerAnnotationsInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecHostsInnerNamesInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreKeyPairsKeysInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreKeyPairsKeysInnerCreateData;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreKeyPairsKeysInnerCreateDataSecretInfo;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreStaticKeysInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreTrustedCertificatesInner;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreKeyPairsKeysInner.ImportIntoKsEnum;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.obj.CertificateData;
import com.tremolosecurity.openunison.obj.WsResponse;
import com.tremolosecurity.openunison.obj.X509Data;
import com.tremolosecurity.openunison.sql.RunSQL;
import com.tremolosecurity.openunison.util.CertUtils;
import com.tremolosecurity.openunison.util.NetUtils;

import io.k8s.JSON.ByteArrayAdapter;
import io.k8s.JSON.DateTypeAdapter;
import io.k8s.JSON.LocalDateTypeAdapter;
import io.k8s.JSON.OffsetDateTimeTypeAdapter;
import io.k8s.JSON.SqlDateTypeAdapter;
import io.k8s.obj.IoK8sApiAdmissionregistrationV1ValidatingWebhook;
import io.k8s.obj.IoK8sApiAdmissionregistrationV1ValidatingWebhookConfiguration;
import io.k8s.obj.IoK8sApimachineryPkgApisMetaV1ObjectMeta;
import io.k8s.obj.IoK8sApiCoreV1Secret;

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

    public boolean load(OpenUnison ou,ClusterConnection cluster,String namespace,String name) throws Exception {
        this.ou = ou;
        this.namespace = namespace;
        this.name = name;
        this.cluster = cluster;
        this.loadPropertiesFromCrd();
        this.loadPropertiesFromSecret();
        this.generateKeyStore();
        this.generateStaticKeys();
        this.generateOpenUnisonSecret();
        this.updateValidatingWebhookCertificate();

        if (this.props.get("OPENUNISON_PROVISIONING_ENABLED") != null && this.props.get("OPENUNISON_PROVISIONING_ENABLED").equalsIgnoreCase("true")) {
            RunSQL runSQL = new RunSQL();
            if (ou.getSpec().getRunSql() != null && ! ou.getSpec().getRunSql().isBlank()) {
                System.out.println("Found SQL");
                runSQL.runSQL(this.ou, this);
            }
            
            return this.setupAmqSecrets();
        } else {
            return false;
        }
    }

    private void generateOpenUnisonSecret() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, ParseException, InterruptedException, URISyntaxException {
        
        KeyStore trustStore = CertUtils.mergeCaCerts(this.ouKs);



        io.k8s.obj.IoK8sApiCoreV1Secret secret = new io.k8s.obj.IoK8sApiCoreV1Secret();
        secret.setData(new HashMap<String,byte[]>());

        

        

        secret.getData().put("openunison.yaml",this.asYaml(this.ou.getSpec().getOpenunisonNetworkConfiguration().toJson()).getBytes("UTF-8"));
        secret.getData().put("ou.env",this.b64EncodeProps());
        secret.getData().put("unisonKeyStore.p12",CertUtils.encodeKeyStoreToBytes(this.ouKs, this.props.get("unisonKeystorePassword")));
        secret.getData().put("cacerts.jks",CertUtils.encodeKeyStoreToBytes(trustStore, "changeit"));

        WsResponse resp = this.cluster.getSecret(this.namespace, this.ou.getSpec().getDestSecret());

        if (resp.getResult() == 200) {


            secret.setMetadata(new IoK8sApimachineryPkgApisMetaV1ObjectMeta());
            secret.getMetadata().setAnnotations(new HashMap<String,String>());
            secret.getMetadata().getAnnotations().put("tremolo.io/last_updated",new DateTime().toString());


            resp = cluster.patch("/api/v1/namespaces/" + namespace + "/secrets/" +  this.ou.getSpec().getDestSecret(), secret.toJson());
            if (resp.getResult() != 200) {
                System.out.println("Problem patching secret - " + resp.getResult() + " / " + resp.getBody().toJSONString());
            } else {
                System.out.println("Secret patched");
            }
        } else {

            secret.setType("Opqaue");
            secret.setApiVersion("v1");
            secret.setKind("Secret");
            secret.setMetadata(new IoK8sApimachineryPkgApisMetaV1ObjectMeta());
            secret.getMetadata().setName(this.ou.getSpec().getDestSecret());
            secret.getMetadata().setNamespace(this.namespace);
            secret.getMetadata().setAnnotations(new HashMap<String,String>());
            secret.getMetadata().getAnnotations().put("tremolo.io/last_updated",new DateTime().toString());

            

            resp = cluster.post("/api/v1/namespaces/" + namespace + "/secrets", secret.toJson());
            if (resp.getResult() != 200) {
                System.out.println("Problem patching secret - " + resp.getResult() + " / " + resp.getBody().toJSONString());
            } else {
                System.out.println("Secret patched");
            }
        }

    }

    private byte[] b64EncodeProps() throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        for (String key : this.props.keySet()) {
            sb.append(key).append('=').append(this.props.get(key)).append('\n');
        }

        return sb.toString().getBytes("UTF-8");
    }

    private void generateStaticKeys() throws Exception {
        String ksPassword = this.props.get("unisonKeystorePassword");
        boolean skipWriteToSecret = this.props.get("openunison.static-secret.skip_write") != null && this.props.get("openunison.static-secret.skip_write").equals("true");
        String secretSuffix = this.props.get("openunison.static-secret.suffix");

        if (secretSuffix == null) {
            secretSuffix = "";
        }


        String secretURI = "/api/v1/namespaces/" + this.namespace + "/secrets/" + this.name + "-static-keys" + secretSuffix;
        System.out.println("Loading static Secrets from " + secretURI);
        WsResponse resp = this.cluster.get(secretURI);

        

        Map<String,JSONObject> staticKeys = new HashMap<String,JSONObject>();
        Map<String,byte[]> dataPatch = new HashMap<String,byte[]>();

        boolean createSecret = true;

        if (resp.getResult() != 200) {
            System.out.println("Could not load Secret: " + resp.getBody() + ", creating");
            
        } else {
            io.k8s.obj.IoK8sApiCoreV1Secret secretFromK8s = io.k8s.JSON.getGson().fromJson(resp.getBody().toString(), io.k8s.obj.IoK8sApiCoreV1Secret.class);
            createSecret = false;
            for (String key : secretFromK8s.getData().keySet()) {
                String keyData = new String(secretFromK8s.getData().get(key));
                
                if (keyData != null) {
                    JSONObject staticKey = (JSONObject) new JSONParser().parse(keyData);
                    staticKey.put("still_used", false);
                    staticKeys.put((String) key, staticKey);
                    
                }
            }
            
        }

        List<String> tokeep = new ArrayList<String>();
        for (OpenUnisonSpecKeyStoreStaticKeysInner staticKey : this.ou.getSpec().getKeyStore().getStaticKeys()) {
            JSONObject staticKeyFromAPI = staticKeys.get(staticKey.getName());
            tokeep.add(staticKey.getName());
            System.out.println("Checking static key " + staticKey.getName());

            if (staticKeyFromAPI == null) {
                System.out.println("the static key doesn't exist in the secret, create it");
                CertUtils.createKey(ouKs, staticKey.getName(), ksPassword );
                JSONObject keyObj = new JSONObject();
                

                keyObj.put("name", staticKey.getName());
                keyObj.put("version",1);
                keyObj.put("key_data",CertUtils.exportKey(ouKs, staticKey.getName(), ksPassword));
                keyObj.put("still_used",true);

                dataPatch.put(staticKey.getName(), keyObj.toString().getBytes("UTF-8"));
            } else if (staticKey.getVersion().intValue() != ((Long)staticKeyFromAPI.get("version")).intValue()) {
                System.out.println("the static key version changed from " +  ((Long)staticKeyFromAPI.get("version")).intValue() + " to " + staticKey.getVersion().intValue()  + ",recreating");
                CertUtils.createKey(ouKs, staticKey.getName(), ksPassword );
                JSONObject keyObj = new JSONObject();
                

                keyObj.put("name", staticKey.getName());
                keyObj.put("version",staticKey.getVersion().intValue());
                keyObj.put("key_data",CertUtils.exportKey(ouKs, staticKey.getName(), ksPassword));
                keyObj.put("still_used",true);

                dataPatch.put(staticKey.getName(), keyObj.toString().getBytes("UTF-8"));
            } else {
                System.out.println("Keeping unchanged");
                dataPatch.put(staticKey.getName(), staticKeyFromAPI.toString().getBytes("UTF-8"));

            }

        }

        for (String key : tokeep) {
            staticKeys.remove(key);
        }

        if (! createSecret) {
            for (String staticKeyToDelete : staticKeys.keySet()) {
                System.out.println("Deleting " + staticKeyToDelete);
                dataPatch.put(staticKeyToDelete, null);
            }
        }

        

        if (! skipWriteToSecret) {

            if (createSecret) {
                System.out.println("Creating a new Secret");
                
                io.k8s.obj.IoK8sApiCoreV1Secret secret = new io.k8s.obj.IoK8sApiCoreV1Secret();
                secret.setType("Opqaue");
                secret.setApiVersion("v1");
                secret.setKind("Secret");
                secret.setMetadata(new IoK8sApimachineryPkgApisMetaV1ObjectMeta());
                secret.getMetadata().setName(this.name + "-static-keys" + secretSuffix);
                secret.getMetadata().setNamespace(this.namespace);
                secret.getMetadata().setAnnotations(new HashMap<String,String>());
                secret.getMetadata().getAnnotations().put("tremolo.io/last_updated",new DateTime().toString());
                secret.setData(dataPatch);

                resp = cluster.post( "/api/v1/namespaces/" + this.namespace + "/secrets", secret.toJson());
                if (resp.getResult() < 200 || resp.getResult() > 299) {
                    throw new Exception("Could not write static secret : " + resp.getResult() + " / " + resp.getBody().toJSONString());
                }
            } else {
                System.out.println("Writing Secret to " + secretURI);
                
                io.k8s.obj.IoK8sApiCoreV1Secret secret = new io.k8s.obj.IoK8sApiCoreV1Secret();
                secret.setMetadata(new IoK8sApimachineryPkgApisMetaV1ObjectMeta());
                secret.getMetadata().setAnnotations(new HashMap<String,String>());
                secret.getMetadata().getAnnotations().put("tremolo.io/last_updated",new DateTime().toString());
                secret.setData(dataPatch);

                String tmpJson = secret.toJson();
                JSONObject secretObj = (JSONObject) new JSONParser().parse(tmpJson);
                JSONObject data = (JSONObject) secretObj.get("data");

                for (String staticKeyToDelete : staticKeys.keySet()) {                    
                    data.put(staticKeyToDelete, null);
                }

                String secretToWrite = secretObj.toString();


                
                resp = cluster.patch(secretURI, secretToWrite);
                if (resp.getResult() < 200 || resp.getResult() > 299) {
                    throw new Exception("Could not write static secret : " + resp.getResult() + " / " + resp.getBody().toJSONString());
                }

            }

            
        } else {
            System.out.println("Writing secret disabled, skipping");
        }

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

        if (this.ou.getSpec().getMyvdConfigmap() != null && ! this.ou.getSpec().getMyvdConfigmap().isBlank())  {
            this.props.put("MYVD_CONFIG_PATH", "/etc/myvd/myvd.conf");
        } else {
            this.props.put("MYVD_CONFIG_PATH", "WEB-INF/myvd.conf");
        }
    

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

    private String asYaml(String jsonString) throws JsonProcessingException, IOException {
        // parse JSON
        JsonNode jsonNodeTree = new ObjectMapper().readTree(jsonString);
        // save it as YAML
        String jsonAsYaml = new YAMLMapper().writeValueAsString(jsonNodeTree);
        return jsonAsYaml;
    }


    

    private void updateValidatingWebhookCertificate() throws Exception {
        String whUriNs = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/openunison-workflow-validation-" + this.name;
        
        System.out.println("Starting webhook check, looking up " + whUriNs);
        WsResponse resp = cluster.get(whUriNs);

        if (resp.getResult() != 200) {
            System.out.println("Unable to load: " + resp.getResult() + " / " + resp.getBody().toJSONString());
            return;
        } 

        java.security.cert.Certificate unisonCert = this.ouKs.getCertificate("unison-tls");

        if (unisonCert == null) {
            System.out.println("unison-tls certificate does not exist, not attempting any updates");
            return;
        }

        

        byte[] unisonCertBytes = unisonCert.getEncoded();

        String fromSecretCertBase64 = java.util.Base64.getEncoder().encodeToString(CertUtils.exportCert((X509Certificate) unisonCert).getBytes("UTF-8"));
        
        io.k8s.obj.IoK8sApiAdmissionregistrationV1ValidatingWebhookConfiguration webHookObj = io.k8s.JSON.getGson().fromJson(resp.getBody().toString(),IoK8sApiAdmissionregistrationV1ValidatingWebhookConfiguration.class);

        
        String fromWh =  new String(java.util.Base64.getEncoder().encode(webHookObj.getWebhooks().get(0).getClientConfig().getCaBundle()));

        if (! fromSecretCertBase64.equals(fromWh)) {
            System.out.println("Webhook needs to be udpated");
            for (IoK8sApiAdmissionregistrationV1ValidatingWebhook wh : webHookObj.getWebhooks()) {
                wh.getClientConfig().setCaBundle(unisonCertBytes);
            }

            io.k8s.obj.IoK8sApiAdmissionregistrationV1ValidatingWebhookConfiguration forPatch = new io.k8s.obj.IoK8sApiAdmissionregistrationV1ValidatingWebhookConfiguration();
            forPatch.setWebhooks(webHookObj.getWebhooks());
            String jsonForPatch = forPatch.toJson();
            resp = cluster.patch(whUriNs, jsonForPatch);
            if (resp.getResult() < 200 || resp.getResult() > 299) {
                throw new Exception("Could not patch webhook : " + resp.getResult() + " / " + resp.getBody().toString());
                
            } else {
                System.out.println("Webhook successfully patched");
            }
        } else {
            System.out.println("Webhook does not need to be udpated");
        }
        

    }

    private boolean setupAmqSecrets() throws Exception {
        boolean updated = false;
        if (! this.ou.getSpec().getEnableActivemq()) {
            System.out.println("ActiveMQ not enabled, skipping");
            return false;
        }

        System.out.println("Processing ActiveMQ Secrets");

        String ksPassword = this.props.get("unisonKeystorePassword");

        KeyStore amqKS = KeyStore.getInstance("PKCS12");
        amqKS.load(null, ksPassword.toCharArray());

        System.out.println("Trusting the amq-client certificate");
        amqKS.setCertificateEntry("trusted-amq-client", this.ouKs.getCertificate("amq-client"));

        WsResponse res = this.cluster.get("/api/v1/namespaces/" + this.namespace + "/secrets/" + this.name + "-amq-server");

        if (res.getResult() != 200) {
            throw new Exception("Could not load secret " + this.name + "-amq-server / " + res.getResult() + " / " + res.getBody().toJSONString());
        }

        IoK8sApiCoreV1Secret amqServerSecret = io.k8s.JSON.getGson().fromJson(res.getBody().toJSONString(), IoK8sApiCoreV1Secret.class);
        CertUtils.importKeyPairAndCert(amqKS, ksPassword, "broker", Base64.getEncoder().encodeToString(amqServerSecret.getData().get("tls.key")), Base64.getEncoder().encodeToString(amqServerSecret.getData().get("tls.crt")));

        String amqSecretUri = "/api/v1/namespaces/" + this.namespace + "/secrets/amq-secrets-" + this.name;
        res = cluster.get(amqSecretUri);

        if (res.getResult() == 200) {
            System.out.println("AMQ Secret already exists");
            IoK8sApiCoreV1Secret amqSecret = io.k8s.JSON.getGson().fromJson(res.getBody().toJSONString(), IoK8sApiCoreV1Secret.class);
            
            String b64ExistingKs = Base64.getEncoder().encodeToString(amqSecret.getData().get("amq.p12"));
            KeyStore existingKs = CertUtils.decodeKeystore(b64ExistingKs, ksPassword);

            boolean keystoresAreSame = false;

            if (existingKs != null) {
                keystoresAreSame = CertUtils.keystoresEqual(amqKS, existingKs, ksPassword);
            }

            if (keystoresAreSame) {
                System.out.println("No changes to AMQ secret");
            } else {
                IoK8sApiCoreV1Secret patch = new IoK8sApiCoreV1Secret();
                patch.setData(new HashMap<String,byte[]>());
                patch.getData().put("amq.p12", CertUtils.encodeKeyStoreToBytes(amqKS, ksPassword));
                res = cluster.patch(amqSecretUri, patch.toJson());

                if (res.getResult() < 200 || res.getResult() >= 299) {
                    throw new Exception("Could not patch amq secret " + amqSecretUri + " / " + res.getResult() + " / " + res.getBody().toJSONString());
                }

                System.out.println("AMQ Secret patched");
                updated = true;
            }
            
        } else {
            String amqConfig = "";
            if (this.props.get("ACTIVEMQ_USE_PVC") != null && this.props.get("ACTIVEMQ_USE_PVC").equalsIgnoreCase("true")) {
                amqConfig = new String(Generator.class.getResourceAsStream("amq-pvc.xml").readAllBytes());
            } else if (this.props.get("OU_JDBC_DRIVER") != null && this.props.get("OU_JDBC_DRIVER").equalsIgnoreCase("com.microsoft.sqlserver.jdbc.SQLServerDriver")) {
                amqConfig = new String(Generator.class.getResourceAsStream("amq-sqlserver.xml").readAllBytes());
            } else {
                amqConfig = new String(Generator.class.getResourceAsStream("amq-mysql.xml").readAllBytes());
            }

            IoK8sApiCoreV1Secret amqSecret = new IoK8sApiCoreV1Secret();
            amqSecret.metadata(
                new IoK8sApimachineryPkgApisMetaV1ObjectMeta()
                .name("amq-secrets-" + this.name)
                .namespace(this.namespace)
            )
            .kind("Secret")
            .type("Opaque")
            .data(new HashMap<String,byte[]>());
            
            amqSecret.getData().put("activemq.xml", amqConfig.getBytes("UTF-8"));
            amqSecret.getData().put("amq.p12",CertUtils.encodeKeyStoreToBytes(amqKS, ksPassword));

            res = cluster.post("/api/v1/namespaces/" + this.namespace + "/secrets", amqSecret.toJson());

            if (res.getResult() < 200 || res.getResult() > 299) {
                throw new Exception("Could not create amq secret " + amqSecretUri + " / " + res.getResult() + " / " + res.getBody().toJSONString());
            }

            updated = true;


        }

        System.out.println("Checking activemq env var secret");

        String forHash = this.props.get("OU_JDBC_DRIVER") + this.props.get("OU_JDBC_URL") + this.props.get("OU_JDBC_USER") + this.props.get("OU_JDBC_PASSWORD") + ksPassword;
        byte[] digestSrc = forHash.getBytes("UTF-8");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(digestSrc, 0, digestSrc.length);
        String newCfgDigest = java.util.Base64.getEncoder().encodeToString(digest.digest());


        IoK8sApiCoreV1Secret amqEnvSecret = new IoK8sApiCoreV1Secret();
        amqEnvSecret.metadata(
                new IoK8sApimachineryPkgApisMetaV1ObjectMeta()
                .annotations(new HashMap<String,String>())
                
            )   
         
        .data(new HashMap<String,byte[]>());    

        amqEnvSecret.getMetadata().getAnnotations().put("tremolo.io/digest",newCfgDigest);

        amqEnvSecret.getData().put("JDBC_DRIVER", this.props.get("OU_JDBC_DRIVER").getBytes("UTF-8"));
        amqEnvSecret.getData().put("JDBC_URL", this.props.get("OU_JDBC_URL").getBytes("UTF-8"));
        amqEnvSecret.getData().put("JDBC_USER", this.props.get("OU_JDBC_USER").getBytes("UTF-8"));
        amqEnvSecret.getData().put("JDBC_PASSWORD", this.props.get("OU_JDBC_PASSWORD").getBytes("UTF-8"));
        amqEnvSecret.getData().put("TLS_KS_PWD", ksPassword.getBytes("UTF-8"));
        

        res = cluster.get("/api/v1/namespaces/" + this.namespace + "/secrets/amq-env-secrets-" + this.name);

        if (res.getResult() == 200) {
            System.out.println("Secret exists, checking if changed");
            IoK8sApiCoreV1Secret secretFromApiServer = io.k8s.JSON.getGson().fromJson(res.getBody().toJSONString(), IoK8sApiCoreV1Secret.class);
            if (secretFromApiServer.getMetadata().getAnnotations() == null || ! secretFromApiServer.getMetadata().getAnnotations().get("tremolo.io/digest").equals(newCfgDigest)) {
                System.out.println("Secret needs to be patched");
                res = cluster.patch("/api/v1/namespaces/" + this.namespace + "/secrets/amq-env-secrets-" + this.name,amqEnvSecret.toJson());

                if (res.getResult() < 200 || res.getResult() >= 299) {
                    throw new Exception("Could not patch amq env secret " + "/api/v1/namespaces/" + this.namespace + "/secrets/amq-env-secrets-" + this.name + " / " + res.getResult() + " / " + res.getBody().toJSONString());
                }

                updated = true;
            } else {
                System.out.println("Secret is unchanged, skipping");
            }
        } else {
            System.out.println("Creating new secret");
            amqEnvSecret.getMetadata().setName("amq-env-secrets-" + this.name);
            amqEnvSecret.getMetadata().setNamespace(this.namespace);
            res = cluster.post("/api/v1/namespaces/" + this.namespace + "/secrets", amqEnvSecret.toJson());

            if (res.getResult() < 200 || res.getResult() > 299) {
                throw new Exception("Could not create amq env secret  " + res.getResult() + " / " + res.getBody().toJSONString());
            }

            updated = true;
        }


        return updated;
    }

    public void deleteSecrets(OpenUnison ou, ClusterConnection cluster,String name) throws Exception {
        this.ou = ou;
        this.cluster = cluster;
        this.namespace = cluster.getNamespace();
        this.name = name;
        this.loadPropertiesFromCrd();
        String ksPassword = this.props.get("unisonKeystorePassword");
        boolean skipWriteToSecret = this.props.get("openunison.static-secret.skip_write") != null && this.props.get("openunison.static-secret.skip_write").equals("true");
        String secretSuffix = this.props.get("openunison.static-secret.suffix");

        if (skipWriteToSecret) {
            System.out.println("openunison.static-secret.skip_write is true, not deleting anything");
            return;
        }

        if (secretSuffix == null) {
            secretSuffix = "";
        }


        



        String uri = "/api/v1/namespaces/" + cluster.getNamespace() + "/secrets/" + this.name + secretSuffix;
        System.out.println("Deleting " + uri);
        cluster.delete(uri);

        uri = "/api/v1/namespaces/" + this.namespace + "/secrets/" + this.name + "-static-keys" + secretSuffix;
        System.out.println("Deleting " + uri);
        cluster.delete(uri);

        for (OpenUnisonSpecKeyStoreKeyPairsKeysInner keySpec : ou.getSpec().getKeyStore().getKeyPairs().getKeys()) {
            System.out.println(keySpec.getName());

            if (keySpec.getCreateData() != null) {
                System.out.println("Has key");
                String secretName = keySpec.getName();
                if (keySpec.getTlsSecretName() != null && ! keySpec.getTlsSecretName().isBlank()) {
                    secretName = keySpec.getTlsSecretName();
                }

                String namespace = this.namespace;
                if (keySpec.getCreateData().getTargetNamespace() != null && ! keySpec.getCreateData().getTargetNamespace().isBlank()) {
                    namespace = keySpec.getCreateData().getTargetNamespace();
                }

                uri = "/api/v1/namespaces/" + namespace + "/secrets/" + secretName + secretSuffix;
                System.out.println("Deleting " + uri);
                cluster.delete(uri);

            }
        }
    }


    private static DateTypeAdapter dateTypeAdapter = new DateTypeAdapter();
    private static SqlDateTypeAdapter sqlDateTypeAdapter = new SqlDateTypeAdapter();
    private static OffsetDateTimeTypeAdapter offsetDateTimeTypeAdapter = new OffsetDateTimeTypeAdapter();
    private static LocalDateTypeAdapter localDateTypeAdapter = new LocalDateTypeAdapter();
    private static ByteArrayAdapter byteArrayAdapter = new ByteArrayAdapter();

    static {
        
            GsonBuilder gsonBuilder = io.k8s.JSON.createGson();
            gsonBuilder.registerTypeAdapter(Date.class, dateTypeAdapter);
            gsonBuilder.registerTypeAdapter(java.sql.Date.class, sqlDateTypeAdapter);
            gsonBuilder.registerTypeAdapter(OffsetDateTime.class, offsetDateTimeTypeAdapter);
            gsonBuilder.registerTypeAdapter(LocalDate.class, localDateTypeAdapter);
            gsonBuilder.registerTypeAdapter(byte[].class, byteArrayAdapter);
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1MatchCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1MutatingWebhook.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1MutatingWebhookConfiguration.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1MutatingWebhookConfigurationList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1RuleWithOperations.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1ServiceReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1ValidatingWebhook.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1ValidatingWebhookConfiguration.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1ValidatingWebhookConfigurationList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1WebhookClientConfig.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1AuditAnnotation.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ExpressionWarning.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1MatchCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1MatchResources.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1NamedRuleWithOperations.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ParamKind.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ParamRef.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1TypeChecking.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ValidatingAdmissionPolicy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ValidatingAdmissionPolicyBinding.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ValidatingAdmissionPolicyBindingList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ValidatingAdmissionPolicyBindingSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ValidatingAdmissionPolicyList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ValidatingAdmissionPolicySpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1ValidatingAdmissionPolicyStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAdmissionregistrationV1alpha1Validation.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiApiserverinternalV1alpha1ServerStorageVersion.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiApiserverinternalV1alpha1StorageVersion.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiApiserverinternalV1alpha1StorageVersionCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiApiserverinternalV1alpha1StorageVersionList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiApiserverinternalV1alpha1StorageVersionStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1ControllerRevision.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1ControllerRevisionList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DaemonSet.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DaemonSetCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DaemonSetList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DaemonSetSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DaemonSetStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DaemonSetUpdateStrategy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1Deployment.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DeploymentCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DeploymentList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DeploymentSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DeploymentStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1DeploymentStrategy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1ReplicaSet.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1ReplicaSetCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1ReplicaSetList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1ReplicaSetSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1ReplicaSetStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1RollingUpdateDaemonSet.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1RollingUpdateDeployment.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1RollingUpdateStatefulSetStrategy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1StatefulSet.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1StatefulSetCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1StatefulSetList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1StatefulSetOrdinals.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1StatefulSetPersistentVolumeClaimRetentionPolicy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1StatefulSetSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1StatefulSetStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAppsV1StatefulSetUpdateStrategy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1BoundObjectReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1TokenRequest.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1TokenRequestSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1TokenRequestStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1TokenReview.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1TokenReviewSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1TokenReviewStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1UserInfo.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1alpha1SelfSubjectReview.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1alpha1SelfSubjectReviewStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1beta1SelfSubjectReview.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthenticationV1beta1SelfSubjectReviewStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1LocalSubjectAccessReview.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1NonResourceAttributes.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1NonResourceRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1ResourceAttributes.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1ResourceRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1SelfSubjectAccessReview.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1SelfSubjectAccessReviewSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1SelfSubjectRulesReview.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1SelfSubjectRulesReviewSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1SubjectAccessReview.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1SubjectAccessReviewSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1SubjectAccessReviewStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAuthorizationV1SubjectRulesReviewStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV1CrossVersionObjectReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV1HorizontalPodAutoscaler.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV1HorizontalPodAutoscalerList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV1HorizontalPodAutoscalerSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV1HorizontalPodAutoscalerStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV1Scale.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV1ScaleSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV1ScaleStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2ContainerResourceMetricSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2ContainerResourceMetricStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2CrossVersionObjectReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2ExternalMetricSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2ExternalMetricStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2HPAScalingPolicy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2HPAScalingRules.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2HorizontalPodAutoscaler.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2HorizontalPodAutoscalerBehavior.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2HorizontalPodAutoscalerCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2HorizontalPodAutoscalerList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2HorizontalPodAutoscalerSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2HorizontalPodAutoscalerStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2MetricIdentifier.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2MetricSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2MetricStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2MetricTarget.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2MetricValueStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2ObjectMetricSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2ObjectMetricStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2PodsMetricSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2PodsMetricStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2ResourceMetricSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiAutoscalingV2ResourceMetricStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1CronJob.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1CronJobList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1CronJobSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1CronJobStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1Job.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1JobCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1JobList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1JobSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1JobStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1JobTemplateSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1PodFailurePolicy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1PodFailurePolicyOnExitCodesRequirement.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1PodFailurePolicyOnPodConditionsPattern.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1PodFailurePolicyRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiBatchV1UncountedTerminatedPods.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCertificatesV1CertificateSigningRequest.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCertificatesV1CertificateSigningRequestCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCertificatesV1CertificateSigningRequestList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCertificatesV1CertificateSigningRequestSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCertificatesV1CertificateSigningRequestStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCertificatesV1alpha1ClusterTrustBundle.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCertificatesV1alpha1ClusterTrustBundleList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCertificatesV1alpha1ClusterTrustBundleSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoordinationV1Lease.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoordinationV1LeaseList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoordinationV1LeaseSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1AWSElasticBlockStoreVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Affinity.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1AttachedVolume.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1AzureDiskVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1AzureFilePersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1AzureFileVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Binding.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1CSIPersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1CSIVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Capabilities.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1CephFSPersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1CephFSVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1CinderPersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1CinderVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ClaimSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ClientIPConfig.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ComponentCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ComponentStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ComponentStatusList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ConfigMap.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ConfigMapEnvSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ConfigMapKeySelector.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ConfigMapList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ConfigMapNodeConfigSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ConfigMapProjection.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ConfigMapVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Container.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ContainerImage.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ContainerPort.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ContainerResizePolicy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ContainerState.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ContainerStateRunning.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ContainerStateTerminated.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ContainerStateWaiting.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ContainerStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1DaemonEndpoint.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1DownwardAPIProjection.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1DownwardAPIVolumeFile.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1DownwardAPIVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EmptyDirVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EndpointAddress.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EndpointPort.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EndpointSubset.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Endpoints.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EndpointsList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EnvFromSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EnvVar.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EnvVarSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EphemeralContainer.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EphemeralVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Event.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EventList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EventSeries.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1EventSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ExecAction.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1FCVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1FlexPersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1FlexVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1FlockerVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1GCEPersistentDiskVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1GRPCAction.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1GitRepoVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1GlusterfsPersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1GlusterfsVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1HTTPGetAction.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1HTTPHeader.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1HostAlias.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1HostPathVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ISCSIPersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ISCSIVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1KeyToPath.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Lifecycle.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1LifecycleHandler.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1LimitRange.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1LimitRangeItem.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1LimitRangeList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1LimitRangeSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1LoadBalancerIngress.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1LoadBalancerStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1LocalObjectReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1LocalVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NFSVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Namespace.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NamespaceCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NamespaceList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NamespaceSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NamespaceStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Node.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeAddress.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeAffinity.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeConfigSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeConfigStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeDaemonEndpoints.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeSelector.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeSelectorRequirement.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeSelectorTerm.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1NodeSystemInfo.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ObjectFieldSelector.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ObjectReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolume.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeClaim.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeClaimCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeClaimList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeClaimSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeClaimStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeClaimTemplate.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeClaimVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PersistentVolumeStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PhotonPersistentDiskVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Pod.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodAffinity.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodAffinityTerm.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodAntiAffinity.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodDNSConfig.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodDNSConfigOption.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodIP.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodOS.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodReadinessGate.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodResourceClaim.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodSchedulingGate.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodSecurityContext.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodTemplate.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodTemplateList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PodTemplateSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PortStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PortworxVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1PreferredSchedulingTerm.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Probe.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ProjectedVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1QuobyteVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1RBDPersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1RBDVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ReplicationController.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ReplicationControllerCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ReplicationControllerList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ReplicationControllerSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ReplicationControllerStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ResourceClaim.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ResourceFieldSelector.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ResourceQuota.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ResourceQuotaList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ResourceQuotaSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ResourceQuotaStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ResourceRequirements.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SELinuxOptions.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ScaleIOPersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ScaleIOVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ScopeSelector.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ScopedResourceSelectorRequirement.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SeccompProfile.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Secret.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SecretEnvSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SecretKeySelector.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SecretList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SecretProjection.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SecretReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SecretVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SecurityContext.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Service.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ServiceAccount.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ServiceAccountList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ServiceAccountTokenProjection.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ServiceList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ServicePort.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ServiceSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1ServiceStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1SessionAffinityConfig.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1StorageOSPersistentVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1StorageOSVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Sysctl.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1TCPSocketAction.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Taint.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Toleration.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1TopologySelectorLabelRequirement.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1TopologySelectorTerm.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1TopologySpreadConstraint.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1TypedLocalObjectReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1TypedObjectReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1Volume.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1VolumeDevice.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1VolumeMount.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1VolumeNodeAffinity.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1VolumeProjection.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1VsphereVirtualDiskVolumeSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1WeightedPodAffinityTerm.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiCoreV1WindowsSecurityContextOptions.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiDiscoveryV1Endpoint.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiDiscoveryV1EndpointConditions.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiDiscoveryV1EndpointHints.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiDiscoveryV1EndpointPort.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiDiscoveryV1EndpointSlice.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiDiscoveryV1EndpointSliceList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiDiscoveryV1ForZone.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiEventsV1Event.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiEventsV1EventList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiEventsV1EventSeries.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2FlowDistinguisherMethod.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2FlowSchema.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2FlowSchemaCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2FlowSchemaList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2FlowSchemaSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2FlowSchemaStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2GroupSubject.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2LimitResponse.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2LimitedPriorityLevelConfiguration.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2NonResourcePolicyRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2PolicyRulesWithSubjects.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2PriorityLevelConfiguration.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2PriorityLevelConfigurationCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2PriorityLevelConfigurationList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2PriorityLevelConfigurationReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2PriorityLevelConfigurationSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2PriorityLevelConfigurationStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2QueuingConfiguration.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2ResourcePolicyRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2ServiceAccountSubject.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2Subject.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta2UserSubject.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3FlowDistinguisherMethod.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3FlowSchema.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3FlowSchemaCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3FlowSchemaList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3FlowSchemaSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3FlowSchemaStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3GroupSubject.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3LimitResponse.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3LimitedPriorityLevelConfiguration.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3NonResourcePolicyRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3PolicyRulesWithSubjects.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3PriorityLevelConfiguration.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3PriorityLevelConfigurationCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3PriorityLevelConfigurationList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3PriorityLevelConfigurationReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3PriorityLevelConfigurationSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3PriorityLevelConfigurationStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3QueuingConfiguration.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3ResourcePolicyRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3ServiceAccountSubject.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3Subject.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiFlowcontrolV1beta3UserSubject.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1HTTPIngressPath.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1HTTPIngressRuleValue.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IPBlock.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1Ingress.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressBackend.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressClass.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressClassList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressClassParametersReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressClassSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressLoadBalancerIngress.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressLoadBalancerStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressPortStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressServiceBackend.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1IngressTLS.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1NetworkPolicy.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1NetworkPolicyEgressRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1NetworkPolicyIngressRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1NetworkPolicyList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1NetworkPolicyPeer.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1NetworkPolicyPort.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1NetworkPolicySpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1NetworkPolicyStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1ServiceBackendPort.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1alpha1ClusterCIDR.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1alpha1ClusterCIDRList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1alpha1ClusterCIDRSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1alpha1IPAddress.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1alpha1IPAddressList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1alpha1IPAddressSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNetworkingV1alpha1ParentReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNodeV1Overhead.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNodeV1RuntimeClass.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNodeV1RuntimeClassList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiNodeV1Scheduling.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiPolicyV1Eviction.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiPolicyV1PodDisruptionBudget.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiPolicyV1PodDisruptionBudgetList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiPolicyV1PodDisruptionBudgetSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiPolicyV1PodDisruptionBudgetStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1AggregationRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1ClusterRole.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1ClusterRoleBinding.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1ClusterRoleBindingList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1ClusterRoleList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1PolicyRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1Role.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1RoleBinding.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1RoleBindingList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1RoleList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1RoleRef.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiRbacV1Subject.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2AllocationResult.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2PodSchedulingContext.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2PodSchedulingContextList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2PodSchedulingContextSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2PodSchedulingContextStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaim.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaimConsumerReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaimList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaimParametersReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaimSchedulingStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaimSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaimStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaimTemplate.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaimTemplateList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClaimTemplateSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClass.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClassList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceClassParametersReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiResourceV1alpha2ResourceHandle.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiSchedulingV1PriorityClass.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiSchedulingV1PriorityClassList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1CSIDriver.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1CSIDriverList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1CSIDriverSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1CSINode.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1CSINodeDriver.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1CSINodeList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1CSINodeSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1CSIStorageCapacity.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1CSIStorageCapacityList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1StorageClass.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1StorageClassList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1TokenRequest.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1VolumeAttachment.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1VolumeAttachmentList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1VolumeAttachmentSource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1VolumeAttachmentSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1VolumeAttachmentStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1VolumeError.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiStorageV1VolumeNodeResources.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceColumnDefinition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceConversion.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceDefinition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceDefinitionCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceDefinitionList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceDefinitionNames.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceDefinitionSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceDefinitionStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceDefinitionVersion.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceSubresourceScale.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceSubresources.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1CustomResourceValidation.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1ExternalDocumentation.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1JSONSchemaProps.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1ServiceReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1ValidationRule.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1WebhookClientConfig.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApiextensionsApiserverPkgApisApiextensionsV1WebhookConversion.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1APIGroup.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1APIGroupList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1APIResource.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1APIResourceList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1APIVersions.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1Condition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1DeleteOptions.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1GroupVersionForDiscovery.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1LabelSelector.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1LabelSelectorRequirement.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1ListMeta.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1ManagedFieldsEntry.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1ObjectMeta.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1OwnerReference.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1Preconditions.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1ServerAddressByClientCIDR.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1Status.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1StatusCause.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1StatusDetails.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgApisMetaV1WatchEvent.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sApimachineryPkgVersionInfo.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sKubeAggregatorPkgApisApiregistrationV1APIService.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sKubeAggregatorPkgApisApiregistrationV1APIServiceCondition.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sKubeAggregatorPkgApisApiregistrationV1APIServiceList.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sKubeAggregatorPkgApisApiregistrationV1APIServiceSpec.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sKubeAggregatorPkgApisApiregistrationV1APIServiceStatus.CustomTypeAdapterFactory());
            gsonBuilder.registerTypeAdapterFactory(new io.k8s.obj.IoK8sKubeAggregatorPkgApisApiregistrationV1ServiceReference.CustomTypeAdapterFactory());
            io.k8s.JSON.setGson(gsonBuilder.create());
        
    
    }
    
    
}
