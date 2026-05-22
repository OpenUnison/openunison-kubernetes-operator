package com.tremolosecurity.openunison.webhooks;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

import org.json.simple.JSONArray;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flipkart.zjsonpatch.JsonDiff;
import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.obj.WsResponse;
import com.tremolosecurity.openunison.secret.Generator;

public class WebHookManager {
    JSONObject ouJson;
    OpenUnison ou;
    ClusterConnection k8s;
    Generator gen;


    public WebHookManager(JSONObject ouJson,OpenUnison ou,ClusterConnection k8s,Generator gen) {
        this.ouJson = ouJson;
        this.ou = ou;
        this.k8s = k8s;
        this.gen = gen;
    }

    public void onAddOrModify() throws Exception {
        JSONArray admissions = (JSONArray) ((JSONObject)ouJson.get("spec")).get("admissions");
        if (admissions == null) {
            admissions = new JSONArray();
        } 


        String caBundle = gen.getInternalCaBundle();
        ObjectMapper mapper = new ObjectMapper();

        Set<String> mutators = new HashSet<>();
        Set<String> validators = new HashSet<>();
        

        for (Object o : admissions) {
            JSONObject webhookcfg = (JSONObject) o;

            boolean isMutator = ((String)webhookcfg.get("type")).equals("mutating");

            if (isMutator) {
                mutators.add((String) webhookcfg.get("name"));
            } else {
                validators.add((String) webhookcfg.get("name"));
            }

            // create header
            JSONObject root = new JSONObject();
            root.put("apiVersion","admissionregistration.k8s.io/v1");
            root.put("kind", isMutator ? "MutatingWebhookConfiguration" : "ValidatingWebhookConfiguration"  );

            JSONObject metadata = new JSONObject();
            root.put("metadata",metadata);
            metadata.put("name",webhookcfg.get("name"));
            
            JSONObject labels = new JSONObject();
            metadata.put("labels",labels);
            labels.put("app.kubernetes.io/name","openunison");
            labels.put("app.kubernetes.io/instance","openunison-" + ou.getMetadata().getName());
            labels.put("app.kubernetes.io/component","configured-webhooks");
            labels.put("app.kubernetes.io/part-of","openunison");
            labels.put("app.kubernetes.io/managed-by","openunison-operator");

            JSONObject annotations = new JSONObject();
            metadata.put("annotations",annotations);
            annotations.put("openunison.tremolo.io/owner-kind","OpenUnison");
            annotations.put("openunison.tremolo.io/owner-name",ou.getMetadata().getName());
            annotations.put("openunison.tremolo.io/owner-namespace",ou.getMetadata().getNamespace());
            annotations.put("openunison.tremolo.io/owner-uid",ou.getMetadata().getUid());

            // for each webhook, add the caBundle
            JSONArray webhooks = (JSONArray) webhookcfg.get("webhooks");
            webhooks = (JSONArray) new JSONParser().parse(webhooks.toString());
            for (Object oo : webhooks) {
                JSONObject webhook = (JSONObject) oo;
                JSONObject clientConfig = (JSONObject) webhook.get("clientConfig");
                clientConfig.put("caBundle",caBundle);
            }

            root.put("webhooks",webhooks);

            String checksumGen = generateCheckSum(generateCleanAC(root));

            String cleanGen = generateCleanAC(root).toString();

            JsonNode genNode = mapper.readTree(cleanGen); 
            

            String currentUri = "/apis/admissionregistration.k8s.io/v1/" + (isMutator ? "mutatingwebhookconfigurations" : "validatingwebhookconfigurations") + "/" + webhookcfg.get("name");
            WsResponse resp = k8s.get(currentUri);
            
            if (resp.getResult() == 404) {
                System.out.println("Webhook " + currentUri + " does not exist, creating");
                String postUri = "/apis/admissionregistration.k8s.io/v1/" + (isMutator ? "mutatingwebhookconfigurations" : "validatingwebhookconfigurations");
                resp = k8s.post(postUri,root.toString());
                if (resp.getResult() != 201) {
                    System.out.println("Could not create webhook " + resp.getResult() + " / " + resp.getBody());
                } else {
                    System.out.println("created");
                }
            } else {
                String cleanFromServer = this.generateCleanAC(resp.getBody()).toString();
                String checkSumFromServer = this.generateCheckSum(this.generateCleanAC(resp.getBody()));
                JsonNode cleanFromServerNode = mapper.readTree(cleanFromServer);


                JsonNode diff = JsonDiff.asJson(genNode,cleanFromServerNode);

                if (diff.size() > 0) {
                    System.out.println("Webhook " + currentUri + " has changed, patching");
                    System.out.println(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(diff));
                    resp = k8s.patch(currentUri,root.toString());
                    if (resp.getResult() != 200) {
                        System.out.println("Could not patch webhook " + resp.getResult() + " / " + resp.getBody());
                    } else {
                        System.out.println("patched");
                    }
                } else {
                    System.out.println("No changes to " + currentUri);
                }
            }

        }

        WsResponse resp = k8s.get("/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations?labelSelector=app.kubernetes.io%2Fcomponent%3Dconfigured-webhooks%2Capp.kubernetes.io%2Finstance%3Dopenunison-" + ou.getMetadata().getName());
        JSONArray items = (JSONArray)resp.getBody().get("items");
        for (Object o : items) {
            JSONObject root = (JSONObject)o;
            JSONObject metadata = (JSONObject) root.get("metadata");
            String name = (String) metadata.get("name");
            if (! mutators.contains(name)) {
                JSONObject annotations = (JSONObject) metadata.get("annotations");
                String namespace = (String) annotations.get("openunison.tremolo.io/owner-namespace");
                if (namespace == null) {
                    namespace = "";
                }

                if (namespace.equalsIgnoreCase(ou.getMetadata().getNamespace())) {
                    System.out.println("Mutating webhook " + name + " no longer configured, deleting");
                    resp = k8s.delete("/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/" + name);
                    if (resp.getResult() == 200) {
                        System.out.println("Deleted");
                    } else {
                        System.out.println("Could not delete mutator " + resp.getResult() + " / " + resp.getBody());
                    }
                }
            }
        }

        resp = k8s.get("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations?labelSelector=app.kubernetes.io%2Fcomponent%3Dconfigured-webhooks%2Capp.kubernetes.io%2Finstance%3Dopenunison-" + ou.getMetadata().getName());
        items = (JSONArray)resp.getBody().get("items");
        for (Object o : items) {
            JSONObject root = (JSONObject)o;
            JSONObject metadata = (JSONObject) root.get("metadata");
            String name = (String) metadata.get("name");
            if (! validators.contains(name)) {
                JSONObject annotations = (JSONObject) metadata.get("annotations");
                String namespace = (String) annotations.get("openunison.tremolo.io/owner-namespace");
                if (namespace == null) {
                    namespace = "";
                }

                if (namespace.equalsIgnoreCase(ou.getMetadata().getNamespace())) {
                    System.out.println("Validating webhook " + name + " no longer configured, deleting");
                    resp = k8s.delete("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/" + name);
                    if (resp.getResult() == 200) {
                        System.out.println("Deleted");
                    } else {
                        System.out.println("Could not delete validator " + resp.getResult() + " / " + resp.getBody());
                    }
                }
            }
        }

    }


    public void onDelete() throws Exception {
        JSONArray admissions = (JSONArray) ((JSONObject)ouJson.get("spec")).get("admissions");
        if (admissions == null) {
            admissions = new JSONArray();
        } 


        

        WsResponse resp = k8s.get("/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations?labelSelector=app.kubernetes.io%2Fcomponent%3Dconfigured-webhooks%2Capp.kubernetes.io%2Finstance%3Dopenunison-" + ou.getMetadata().getName());
        JSONArray items = (JSONArray)resp.getBody().get("items");
        for (Object o : items) {
            JSONObject root = (JSONObject)o;
            JSONObject metadata = (JSONObject) root.get("metadata");
            String name = (String) metadata.get("name");
            if (! mutators.contains(name)) {
                JSONObject annotations = (JSONObject) metadata.get("annotations");
                String namespace = (String) annotations.get("openunison.tremolo.io/owner-namespace");
                if (namespace == null) {
                    namespace = "";
                }

                if (namespace.equalsIgnoreCase(ou.getMetadata().getNamespace())) {
                    System.out.println("Mutating webhook " + name + " no longer configured, deleting");
                    resp = k8s.delete("/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations/" + name);
                    if (resp.getResult() == 200) {
                        System.out.println("Deleted");
                    } else {
                        System.out.println("Could not delete mutator " + resp.getResult() + " / " + resp.getBody());
                    }
                }
            }
        }

        resp = k8s.get("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations?labelSelector=app.kubernetes.io%2Fcomponent%3Dconfigured-webhooks%2Capp.kubernetes.io%2Finstance%3Dopenunison-" + ou.getMetadata().getName());
        items = (JSONArray)resp.getBody().get("items");
        for (Object o : items) {
            JSONObject root = (JSONObject)o;
            JSONObject metadata = (JSONObject) root.get("metadata");
            String name = (String) metadata.get("name");
            
            JSONObject annotations = (JSONObject) metadata.get("annotations");
            String namespace = (String) annotations.get("openunison.tremolo.io/owner-namespace");
            if (namespace == null) {
                namespace = "";
            }

            
            System.out.println("Validating webhook " + name + " no longer configured, deleting");
            resp = k8s.delete("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations/" + name);
            if (resp.getResult() == 200) {
                System.out.println("Deleted");
            } else {
                System.out.println("Could not delete validator " + resp.getResult() + " / " + resp.getBody());
            }
                
            
        }

    }

    private String generateCheckSum(JSONObject chkObj)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String jsonForChecksum = chkObj.toJSONString();
        MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        digest.update(jsonForChecksum.getBytes("UTF-8"), 0, jsonForChecksum.getBytes("UTF-8").length);
        byte[] digestBytes = digest.digest();
        String digestBase64 = java.util.Base64.getEncoder().encodeToString(digestBytes);
        return digestBase64;
    }

    private  JSONObject generateCleanAC(JSONObject cr) throws org.json.simple.parser.ParseException {
        JSONParser parser = new JSONParser();

        JSONObject chkObj = new JSONObject();
        chkObj.put("apiVersion", cr.get("apiVersion"));
        chkObj.put("kind", cr.get("kind"));
        chkObj.put("webhooks", cr.get("webhooks"));

        JSONObject metadata = (JSONObject) parser.parse(((JSONObject) cr.get("metadata")).toJSONString());

        metadata.remove("creationTimestamp");
        metadata.remove("generation");
        metadata.remove("resourceVersion");
        metadata.remove("managedFields");
        metadata.remove("uid");

        chkObj.put("metadata", metadata);
        return chkObj;
    }
}


    

