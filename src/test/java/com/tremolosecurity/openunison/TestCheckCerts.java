package com.tremolosecurity.openunison;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.text.ParseException;
import java.util.ArrayList;

import javax.net.ssl.SSLContext;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.tremolosecurity.openunison.certs.CheckCerts;
import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.crd.OpenUnisonSpec;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStore;
import com.tremolosecurity.openunison.crd.OpenUnisonSpecKeyStoreUpdateController;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.obj.WsResponse;
import com.tremolosecurity.openunison.secret.Generator;

public class TestCheckCerts {
    static com.tremolosecurity.openunison.kubernetes.ClusterConnection cluster;

    @BeforeAll
    public static void setup() throws Exception {
        cluster = new ClusterConnection(System.getenv("API_SERVER_URL"),"openunison",System.getenv("PATH_TO_CA_CRT"),System.getenv("PATH_TO_TOKEN"),new String[]{"2","3","4","5","6","7"});
        init();
    }


    private static void init() throws Exception {
        cluster.findVersion();
        JSON.setGson(JSON.createGson().create());
        Generator g = new Generator();
    }

    @Test
    public void testRunCertCheckRecreateAllCerts() throws Exception {
        Generator gen = new Generator();
        
        OpenUnison ou = this.loadOrchestra();

        // first shutdown the operator if its running
        boolean operatorRunning = false;
        WsResponse resp = cluster.get("/apis/apps/v1/namespaces/openunison/deployments/openunison-operator");
        if (resp.getResult() == 200) {
            operatorRunning = true;
            String patch = "{\"spec\":{\"replicas\":0}}";
            resp = cluster.patch("/apis/apps/v1/namespaces/openunison/deployments/openunison-operator", patch);
            
            int numTries = 0;
            boolean done = false;
            while (! done) {
                resp = cluster.get("/api/v1/namespaces/openunison/pods?labelSelector=app%3Dopenunison-operator");
                JSONArray items = (JSONArray) resp.getBody().get("items");
                if (items.size() != 0)  {
                    if (numTries >= 150) {
                        throw new Exception("Timeout waiting for operator to stop");
                    }
                    Thread.sleep(1000);
                    numTries++;
                    System.out.println("waiting for operator to stop: " + numTries);
                } else {
                    done = true;
                }
            }
        }

        // first load secrets
        String unisonTlsUid = getSecretUUID("unison-tls");
        String unisonSaml2RpSigUid = getSecretUUID("unison-saml2-rp-sig");
        String remoteK8sIdpSig = getSecretUUID("remote-k8s-idp-sig");
        String dashboardCert = getSecretUUID("kubernetes-dashboard", "kubernetes-dashboard-certs");

        // patch OpenUnison to force updates
        OpenUnison patch = new OpenUnison();
        patch.setSpec(new OpenUnisonSpec());
        patch.getSpec().setKeyStore(new OpenUnisonSpecKeyStore());
        patch.getSpec().getKeyStore().setUpdateController(new OpenUnisonSpecKeyStoreUpdateController());
        patch.getSpec().getKeyStore().getUpdateController().setDaysToExpire(366);
        cluster.patch("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra", patch.toJson());

        new CheckCerts().checkCerts(cluster);

        // check if deleted
        assertEquals(404,cluster.getSecret("openunison", "unison-tls").getResult() );
        assertEquals(404,cluster.getSecret("openunison", "unison-saml2-rp-sig").getResult() );
        assertEquals(404,cluster.getSecret("openunison", "remote-k8s-idp-sig").getResult() );
        assertEquals(404,cluster.getSecret("kubernetes-dashboard", "kubernetes-dashboard-certs").getResult() );

        
        gen.load(ou, cluster, "openunison", "orchestra",new ArrayList<String>(),new ArrayList<String>());

        assertNotEquals(unisonTlsUid,getSecretUUID("unison-tls"));
        assertNotEquals(unisonSaml2RpSigUid,getSecretUUID("unison-saml2-rp-sig"));
        assertNotEquals(remoteK8sIdpSig,getSecretUUID("remote-k8s-idp-sig"));
        assertNotEquals(dashboardCert,getSecretUUID("kubernetes-dashboard", "kubernetes-dashboard-certs"));

        patch.getSpec().getKeyStore().getUpdateController().setDaysToExpire(10);
        cluster.patch("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra", patch.toJson());


        int numTries = 0;
        boolean done = false;
        while (! done) {
            resp = cluster.get("/api/v1/namespaces/openunison/pods?labelSelector=app%3Dopenunison-orchestra");
            JSONArray items = (JSONArray) resp.getBody().get("items");
            if (items.size() != 1)  {
                if (numTries >= 150) {
                    throw new Exception("Timeout waiting for openunison to start");
                }
                Thread.sleep(1000);
                numTries++;
                System.out.println("waiting for openunison to start: " + numTries);
            } else {
                done = true;
            }
        }

        if (operatorRunning) {
            String patchx = "{\"spec\":{\"replicas\":1}}";
            resp = cluster.patch("/apis/apps/v1/namespaces/openunison/deployments/openunison-operator", patchx);
            
            
        }

    }

    @Test
    public void testRunCertCheckLeaveAllCerts() throws Exception {
        Generator gen = new Generator();
        
        OpenUnison ou = this.loadOrchestra();

        // first shutdown the operator if its running
        boolean operatorRunning = false;
        WsResponse resp = cluster.get("/apis/apps/v1/namespaces/openunison/deployments/openunison-operator");
        if (resp.getResult() == 200) {
            operatorRunning = true;
            String patch = "{\"spec\":{\"replicas\":0}}";
            resp = cluster.patch("/apis/apps/v1/namespaces/openunison/deployments/openunison-operator", patch);
            
            int numTries = 0;
            boolean done = false;
            while (! done) {
                resp = cluster.get("/api/v1/namespaces/openunison/pods?labelSelector=app%3Dopenunison-operator");
                JSONArray items = (JSONArray) resp.getBody().get("items");
                if (items.size() != 0)  {
                    if (numTries >= 150) {
                        throw new Exception("Timeout waiting for operator to stop");
                    }
                    Thread.sleep(1000);
                    numTries++;
                    System.out.println("waiting for operator to stop: " + numTries);
                } else {
                    done = true;
                }
            }
        }

        // first load secrets
        String unisonTlsUid = getSecretUUID("unison-tls");
        String unisonSaml2RpSigUid = getSecretUUID("unison-saml2-rp-sig");
        String remoteK8sIdpSig = getSecretUUID("remote-k8s-idp-sig");
        String dashboardCert = getSecretUUID("kubernetes-dashboard", "kubernetes-dashboard-certs");

        // patch OpenUnison to force updates
        OpenUnison patch = new OpenUnison();
        patch.setSpec(new OpenUnisonSpec());
        patch.getSpec().setKeyStore(new OpenUnisonSpecKeyStore());
        patch.getSpec().getKeyStore().setUpdateController(new OpenUnisonSpecKeyStoreUpdateController());
        patch.getSpec().getKeyStore().getUpdateController().setDaysToExpire(10);
        cluster.patch("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra", patch.toJson());

        new CheckCerts().checkCerts(cluster);

        // check if deleted
        assertEquals(200,cluster.getSecret("openunison", "unison-tls").getResult() );
        assertEquals(200,cluster.getSecret("openunison", "unison-saml2-rp-sig").getResult() );
        assertEquals(200,cluster.getSecret("openunison", "remote-k8s-idp-sig").getResult() );
        assertEquals(200,cluster.getSecret("kubernetes-dashboard", "kubernetes-dashboard-certs").getResult() );

        
        gen.load(ou, cluster, "openunison", "orchestra",new ArrayList<String>(),new ArrayList<String>());

        assertEquals(unisonTlsUid,getSecretUUID("unison-tls"));
        assertEquals(unisonSaml2RpSigUid,getSecretUUID("unison-saml2-rp-sig"));
        assertEquals(remoteK8sIdpSig,getSecretUUID("remote-k8s-idp-sig"));
        assertEquals(dashboardCert,getSecretUUID("kubernetes-dashboard", "kubernetes-dashboard-certs"));

        patch.getSpec().getKeyStore().getUpdateController().setDaysToExpire(10);
        cluster.patch("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra", patch.toJson());


        int numTries = 0;
        boolean done = false;
        while (! done) {
            resp = cluster.get("/api/v1/namespaces/openunison/pods?labelSelector=app%3Dopenunison-orchestra");
            JSONArray items = (JSONArray) resp.getBody().get("items");
            if (items.size() != 1)  {
                if (numTries >= 150) {
                    throw new Exception("Timeout waiting for openunison to start");
                }
                Thread.sleep(1000);
                numTries++;
                System.out.println("waiting for openunison to start: " + numTries);
            } else {
                done = true;
            }
        }

        if (operatorRunning) {
            String patchx = "{\"spec\":{\"replicas\":1}}";
            resp = cluster.patch("/apis/apps/v1/namespaces/openunison/deployments/openunison-operator", patchx);
            
            
        }

    }


    private String getSecretUUID(String name) throws Exception {
        JSONObject secret = cluster.getSecret("openunison", name).getBody();
        JSONObject metadata = (JSONObject) secret.get("metadata");
        return (String) metadata.get("uid");
    }

    private String getSecretUUID(String namespace,String name) throws Exception {
        JSONObject secret = cluster.getSecret(namespace, name).getBody();
        JSONObject metadata = (JSONObject) secret.get("metadata");
        return (String) metadata.get("uid");
    }

    private com.tremolosecurity.openunison.crd.OpenUnison loadOrchestra()
            throws Exception, URISyntaxException, IOException, InterruptedException, ParseException {
        init();
        

        SSLContext sslCtx = cluster.generateSSLContext();
        HttpClient http = HttpClient.newBuilder()
                            .sslContext(sslCtx)
                            .build();

        HttpRequest get = HttpRequest.newBuilder()
                            .uri(new URI(cluster.getWatchUrl() + "/orchestra"))
                            .GET()
                            .header("Authorization", String.format("Bearer %s", cluster.loadToken()))
                            .build();

        HttpResponse<String> resp = http.send(get,BodyHandlers.ofString());

        assertEquals(resp.statusCode(),200);

        JSONObject json = (JSONObject) new JSONParser().parse(resp.body());

        json.remove("metadata");
        json.remove("kind");
        json.remove("apiVersion");

        com.tremolosecurity.openunison.crd.OpenUnison ou = JSON.getGson().fromJson(json.toString(), OpenUnison.class);
        return ou;
    }
}
