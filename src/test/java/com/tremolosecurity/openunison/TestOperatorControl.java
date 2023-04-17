package com.tremolosecurity.openunison;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.UUID;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.obj.WsResponse;
import com.tremolosecurity.openunison.operator.Operator;
import com.tremolosecurity.openunison.secret.Generator;

public class TestOperatorControl {
    static com.tremolosecurity.openunison.kubernetes.ClusterConnection cluster;

    @BeforeAll
    public static void setup() throws Exception {
        cluster = new ClusterConnection(System.getenv("API_SERVER_URL"),"openunison",System.getenv("PATH_TO_CA_CRT"),System.getenv("PATH_TO_TOKEN"),new String[]{"2","3","4","5","6","7"});
        init();
    }

    


    @Test
    public void testDelete() throws Exception {
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

        resp = cluster.get("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra");
        assertEquals(200,resp.getResult());

        assertEquals(200,cluster.get("/api/v1/namespaces/openunison/secrets/orchestra").getResult());
        assertEquals(200,cluster.get("/api/v1/namespaces/openunison/secrets/orchestra-static-keys").getResult());
        assertEquals(200,cluster.get("/api/v1/namespaces/openunison/secrets/unison-tls").getResult());
        assertEquals(200,cluster.get("/api/v1/namespaces/openunison/secrets/unison-saml2-rp-sig").getResult());
        assertEquals(200,cluster.get("/api/v1/namespaces/openunison/secrets/remote-k8s-idp-sig").getResult());


        resp.getBody().remove("status");
        ((JSONObject)resp.getBody().get("metadata")).remove("resourceVersion");
        ((JSONObject)resp.getBody().get("metadata")).remove("uid");


        Operator operator = new Operator(cluster,5);
        operator.init();

        new Thread() {
            @Override
            public void run() {
                try {
                    operator.runWatch();
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }.start();


        JSONObject ouobj = resp.getBody();
        resp = cluster.delete("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra");
        assertEquals(200,resp.getResult());

        System.out.println("Waiting a few seconds");
        Thread.sleep(5000);

        // make checks
        assertEquals(404,cluster.get("/api/v1/namespaces/openunison/secrets/orchestra").getResult());
        assertEquals(404,cluster.get("/api/v1/namespaces/openunison/secrets/orchestra-static-keys").getResult());
        assertEquals(404,cluster.get("/api/v1/namespaces/openunison/secrets/unison-tls").getResult());
        assertEquals(404,cluster.get("/api/v1/namespaces/openunison/secrets/unison-saml2-rp-sig").getResult());
        assertEquals(404,cluster.get("/api/v1/namespaces/openunison/secrets/remote-k8s-idp-sig").getResult());
        



        // cleanup
        resp = cluster.post("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons", ouobj.toJSONString());
        assertEquals(201,resp.getResult());






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
            String patch = "{\"spec\":{\"replicas\":1}}";
            resp = cluster.patch("/apis/apps/v1/namespaces/openunison/deployments/openunison-operator", patch);
            
            
        }

    }



    @Test
    public void testOperatorNew() throws Exception {

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

        // get ou
        resp = cluster.get("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra");
        com.tremolosecurity.openunison.crd.OpenUnison originalOu = JSON.getGson().fromJson(resp.getBody().toString(), OpenUnison.class);

        // patch to force update on operator start
        String ouPatch = "{\"metadata\":{\"annotations\":{\"forceupdate\":\""  +  UUID.randomUUID().toString()  + "\"}}}";
        resp = cluster.patch("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra",ouPatch);
        assertEquals(200,resp.getResult());


        Operator operator = new Operator(cluster,5);
        operator.init();


        // get latest ou
        resp = cluster.get("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra");
        com.tremolosecurity.openunison.crd.OpenUnison newOu = JSON.getGson().fromJson(resp.getBody().toString(), OpenUnison.class);

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
            String patch = "{\"spec\":{\"replicas\":1}}";
            resp = cluster.patch("/apis/apps/v1/namespaces/openunison/deployments/openunison-operator", patch);
            
            
        }

        assertNotEquals(originalOu.getStatus().getDigest(), newOu.getStatus().getDigest());



    }
    
    
    @Test
    public void testOperatorWatch() throws Exception {
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

        resp = cluster.get("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra");

        resp.getBody().remove("metadata");
        resp.getBody().remove("kind");
        resp.getBody().remove("apiVersion");

        com.tremolosecurity.openunison.crd.OpenUnison originalOu = JSON.getGson().fromJson(resp.getBody().toString(), OpenUnison.class);

        // do stuff
        
        Operator operator = new Operator(cluster,5);
        operator.init();

        // make sure nothing has changed on init run
        System.out.println("Sleeping for 2 seconds");
        resp = cluster.get("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra");
        com.tremolosecurity.openunison.crd.OpenUnison newOu = JSON.getGson().fromJson(resp.getBody().toString(), OpenUnison.class);
        assertEquals(originalOu.getStatus().getDigest(),newOu.getStatus().getDigest());
        
        
        new Thread() {
            @Override
            public void run() {
                try {
                    operator.runWatch();
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }.start();
        
        
        
        String ouPatch = "{\"metadata\":{\"annotations\":{\"forceupdate\":\""  +  UUID.randomUUID().toString()  + "\"}}}";
        resp = cluster.patch("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra",ouPatch);
        assertEquals(200,resp.getResult());

        

        



        // wait for everything to settle

        System.out.println("Sleeping for 10 seconds");
        Thread.sleep(10000);
        resp = cluster.get("/apis/openunison.tremolo.io/v6/namespaces/openunison/openunisons/orchestra");

        //resp.getBody().remove("metadata");
        //resp.getBody().remove("kind");
        //resp.getBody().remove("apiVersion");

        newOu = JSON.getGson().fromJson(resp.getBody().toString(), OpenUnison.class);


        

        
        

        
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
                System.out.println("waiting for operator to start: " + numTries);
            } else {
                done = true;
            }
        }
        

        if (operatorRunning) {
            String patch = "{\"spec\":{\"replicas\":1}}";
            resp = cluster.patch("/apis/apps/v1/namespaces/openunison/deployments/openunison-operator", patch);
            
            
        }



        operator.endWatch();

        assertNotEquals(originalOu.getStatus().getDigest(), newOu.getStatus().getDigest());
    } 

    private static void init() throws Exception {
        cluster.findVersion();
        JSON.setGson(JSON.createGson().create());
        Generator g = new Generator();
    }
}
