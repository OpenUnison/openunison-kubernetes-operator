package com.tremolosecurity.openunison.kubernetes;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.UUID;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.openunison.obj.WsResponse;
import com.tremolosecurity.openunison.util.CertUtils;

public class ClusterConnection {
    String pathToCert;
    String pathToToken;
    String url;
    String namespace;
    String[] versions;

    String version;

    String watchUrl;

    SSLContext sslCtx;
    HttpClient http;

    String uriPath;

    public ClusterConnection(String url,String namespace, String pathToCert, String pathToToken,String[] versions) {
        this.url = url;
        this.namespace = namespace;
        this.pathToCert = pathToCert;
        this.pathToToken = pathToToken;
        this.versions = versions;
    }

    public WsResponse getSecret(String namespace,String name) throws ParseException, IOException, InterruptedException, URISyntaxException {
        String secretUrl = "/api/v1/namespaces/" + namespace + "/secrets/" +  name;
        
        WsResponse wsresp = get(secretUrl);
        return wsresp;
    }

    public WsResponse get(String secretUrl)
            throws URISyntaxException, IOException, InterruptedException, ParseException {
        HttpRequest get = HttpRequest.newBuilder()
                                        .uri(new URI(this.url + secretUrl))
                                        .GET()
                                        .header("Authorization", String.format("Bearer %s", this.loadToken()))
                                        .build();

        HttpResponse<String> resp = http.send(get,BodyHandlers.ofString());

        WsResponse wsresp = new WsResponse(resp.statusCode(),(JSONObject) new JSONParser().parse(resp.body()));
        return wsresp;
    } 

    public void findVersion() throws Exception {
        this.sslCtx = this.generateSSLContext();  
        this.http = HttpClient.newBuilder()
                    .sslContext(sslCtx)
                    .build();

        for (int i = versions.length - 1; i>= 0;i--) {
            System.out.println("Testing version " + this.versions[i]);
            String urlToTest = String.format("%s/apis/openunison.tremolo.io/v%s/namespaces/%s/openunisons",this.url,versions[i],this.namespace);
            this.uriPath = String.format("/apis/openunison.tremolo.io/v%s/namespaces/%s/openunisons",versions[i],this.namespace);
            System.out.println("URL: " + urlToTest); 

            HttpRequest get = HttpRequest.newBuilder()
                                        .uri(new URI(urlToTest))
                                        .GET()
                                        .header("Authorization", String.format("Bearer %s", this.loadToken()))
                                        .build();

            HttpResponse<String> resp = http.send(get,BodyHandlers.ofString());
            if (resp.statusCode() >= 200 && resp.statusCode() < 300) {
                this.watchUrl = urlToTest;
                break;
            } else if (resp.statusCode() != 404) {
                throw new Exception("Unknown status code: " + resp.statusCode() + " / " + resp.body());
                
            } else {
                System.out.println("Not found, next version");
            }

            

            
        }

        System.out.println("Watch URL: " + this.watchUrl);
    }

    public String loadToken() {
        try {
            return Files.readString(Path.of(this.pathToToken));
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }

    public SSLContext generateSSLContext() throws Exception {

        String tmppass = UUID.randomUUID().toString();

        String certPem = Files.readString(Path.of(this.pathToCert));


        

        
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null,tmppass.toCharArray());

        CertUtils.importCertificate(ks, tmppass, "k8s-api-server", certPem);

        

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(ks, tmppass.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ks);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;

    }

    public String getPathToCert() {
        return pathToCert;
    }

    public String getPathToToken() {
        return pathToToken;
    }

    public String getUrl() {
        return url;
    }

    public String getNamespace() {
        return namespace;
    }

    public String[] getVersions() {
        return versions;
    }

    public String getVersion() {
        return version;
    }

    public String getWatchUrl() {
        return watchUrl;
    }

    public WsResponse delete(String uri) throws URISyntaxException, IOException, InterruptedException, ParseException {
        HttpRequest get = HttpRequest.newBuilder()
        .uri(new URI(this.url + uri))
        .DELETE()
        .header("Authorization", String.format("Bearer %s", this.loadToken()))
        .build();

        HttpResponse<String> resp = http.send(get,BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            System.out.println(String.format("There was a problem deleteing %s: %s / %s", uri, resp.statusCode(),resp.body()));
        }

        WsResponse wsresp = new WsResponse(resp.statusCode(),(JSONObject) new JSONParser().parse(resp.body()));
        return wsresp;
    }

    public WsResponse post(String uri, String json) throws URISyntaxException, IOException, InterruptedException, ParseException {
        HttpRequest get = HttpRequest.newBuilder()
        .uri(new URI(this.url + uri))
        .POST(BodyPublishers.ofString(json))
        .header("Authorization", String.format("Bearer %s", this.loadToken()))
        .header("Content-type", "application/json")
        .build();

        HttpResponse<String> resp = http.send(get,BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            System.out.println(String.format("There was a problem posting %s: %s / %s", uri, resp.statusCode(),resp.body()));
        }

        WsResponse wsresp = new WsResponse(resp.statusCode(),(JSONObject) new JSONParser().parse(resp.body()));
        return wsresp;
    }

    public WsResponse patch(String uri, String json) throws URISyntaxException, IOException, InterruptedException, ParseException {
        HttpRequest get = HttpRequest.newBuilder()
        .uri(new URI(this.url + uri))
        .method("PATCH",BodyPublishers.ofString(json))
        .header("Authorization", String.format("Bearer %s", this.loadToken()))
        .header("Content-type", "application/merge-patch+json")
        .build();

        HttpResponse<String> resp = http.send(get,BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            System.out.println(String.format("There was a problem posting %s: %s / %s", uri, resp.statusCode(),resp.body()));
        }

        WsResponse wsresp = new WsResponse(resp.statusCode(),(JSONObject) new JSONParser().parse(resp.body()));
        return wsresp;
    }

    public String getUriPath() {
        return uriPath;
    }
    
}
