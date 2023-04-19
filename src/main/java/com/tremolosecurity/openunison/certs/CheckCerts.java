package com.tremolosecurity.openunison.certs;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

import org.joda.time.DateTime;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreKeyPairsKeysInner;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.obj.WsResponse;
import com.tremolosecurity.openunison.util.CertUtils;

import io.k8s.JSON;
import io.k8s.obj.IoK8sApiCoreV1Secret;

public class CheckCerts {
    public void checkCerts(ClusterConnection cluster) throws Exception {
        com.tremolosecurity.openunison.JSON.setGson(com.tremolosecurity.openunison.JSON.createGson().create());
        SSLContext sslCtx = cluster.generateSSLContext();
        HttpClient http = HttpClient.newBuilder()
                            .sslContext(sslCtx)
                            .build();

        HttpRequest get = HttpRequest.newBuilder()
                            .uri(new URI(cluster.getWatchUrl()))
                            .GET()
                            .header("Authorization", String.format("Bearer %s", cluster.loadToken()))
                            .build();

        HttpResponse<String> resp = http.send(get,BodyHandlers.ofString());

        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            System.err.println("Could not load " + cluster.getWatchUrl() +" - " + resp.statusCode() + " / " + resp.body());
            System.exit(1);
        } else {
            String json = resp.body();
            
            
            JSONObject root = (JSONObject) new JSONParser().parse(json);
            JSONArray items = (JSONArray) root.get("items");
            for (Object o : items) {
                JSONObject obj = (JSONObject) o;
                JSONObject metadata = (JSONObject) obj.get("metadata");
                String namespace = (String) metadata.get("namespace");
                String name = (String) metadata.get("name");
                boolean needToPatch = false;
                
                OpenUnison ou = com.tremolosecurity.openunison.JSON.getGson().fromJson(obj.toJSONString(), OpenUnison.class);
                System.out.println("Checking " + namespace + " / " + name);
                for (OpenUnisonSpecKeyStoreKeyPairsKeysInner keyData : ou.getSpec().getKeyStore().getKeyPairs().getKeys() ){
                    System.out.println(keyData.getName());
                    String knamespace = cluster.getNamespace();
                    String kname = keyData.getName();

                    if (keyData.getTlsSecretName() != null && ! keyData.getTlsSecretName().isBlank()) {
                        kname = keyData.getTlsSecretName();
                    }

                    if (keyData.getCreateData() != null && keyData.getCreateData().getTargetNamespace() != null && ! keyData.getCreateData().getTargetNamespace().isBlank()) {
                        knamespace = keyData.getCreateData().getTargetNamespace();
                    }

                    System.out.println("Secret stored in " + knamespace + " / " + kname);
                    JSONObject secretJson = null;
                    try {
                        WsResponse wresp = cluster.getSecret(knamespace, kname);
                        if (wresp.getResult() == 404) {
                            System.out.println("Not found, skipping");
                            
                        } else if (wresp.getResult() != 200) {
                            System.out.println("Secret not found " + wresp.getResult() + " / " + wresp.getBody().toJSONString());
                            return;
                        } else {
                            
                            JSONObject smetadata = (JSONObject) wresp.getBody().get("metadata");
                            JSONObject slabels = (JSONObject) smetadata.get("labels");

                            if (slabels != null && slabels.get("operated-by") != null && ((String) slabels.get("operated-by")).equalsIgnoreCase("openunison-operator")) {


                                String certName = "tls.crt";
                                if (keyData.getCreateData() != null && keyData.getCreateData().getSecretInfo() != null && keyData.getCreateData().getSecretInfo().getCertName() != null && ! keyData.getCreateData().getSecretInfo().getCertName().isBlank()) {
                                    certName = keyData.getCreateData().getSecretInfo().getCertName();
                                }

                                System.out.println("Checking key " + certName);

                                boolean deleteSecret = false;
                                JSONObject data = (JSONObject) wresp.getBody().get("data");
                                if (data == null) {
                                    System.out.println("Secret has no data, deleting...");
                                    deleteSecret = true;
                                } else {
                                    String b64Cert = (String) data.get(certName);
                                    if (b64Cert == null) {
                                        System.out.println("Key " + certName + " not found, deleting...");
                                        deleteSecret = true;
                                    } else {
                                        try {
                                            X509Certificate certToCheck = CertUtils.pem2cert(new String(java.util.Base64.getDecoder().decode(b64Cert)));
                                            if (CertUtils.isCertExpiring(certToCheck, ou.getSpec().getKeyStore().getUpdateController().getDaysToExpire())) {
                                                System.out.println("Expiring, needs to be recreated");
                                                deleteSecret = true;
                                            } else {
                                                System.out.println("Not expiring");
                                            }
                                        } catch (Exception e) {
                                            System.out.println("Could not parse certificate, deleting...");
                                            deleteSecret = true;
                                            e.printStackTrace();
                                        }
                                    }
                                }

                                if (deleteSecret) {
                                    String uri = "/api/v1/namespaces/" + knamespace + "/secrets/" + kname;
                                    System.out.println("Deleting :" + uri);
                                    wresp = cluster.delete(uri);
                                    if (wresp.getResult() < 200 || wresp.getResult() > 299) {
                                        System.out.println("Unable to delete : " + wresp.getResult() + " / " + wresp.getBody());
                                    } 
                                    needToPatch = true;
                                }
                            } else {
                                System.out.println("Not operated by OpenUnison, skipping");
                            }
                            

                        }
                    } catch (ParseException | IOException | InterruptedException | URISyntaxException e) {
                        e.printStackTrace();
                        
                    }
                    



                    
                }

                if (needToPatch) {
                    JSONObject proot = new JSONObject();
                    JSONObject pmetadata = new JSONObject();
                    proot.put("metadata", pmetadata);
                    JSONObject pannotations = new JSONObject();
                    pmetadata.put("annotations",pannotations);
                    pannotations.put("tremolo.io/cert-manager", DateTime.now().toString());

                    String patchUri = cluster.getUriPath() + "/" + name;
                    System.out.println("Forcing update with patch to " + patchUri);
                    
                    WsResponse presp = cluster.patch(patchUri, json);
                    if (presp.getResult() < 200 || presp.getResult() > 299) {
                        System.out.println("Could not patch " + presp.getResult() + " / " + presp.getBody().toString());
                    }
                }
            }
        }
    }
}
