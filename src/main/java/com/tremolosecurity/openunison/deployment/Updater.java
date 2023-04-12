package com.tremolosecurity.openunison.deployment;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.HashMap;

import org.joda.time.DateTime;
import org.json.simple.parser.ParseException;

import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.obj.WsResponse;

import io.k8s.obj.IoK8sApimachineryPkgApisMetaV1ObjectMeta;



public class Updater {
    String name;
    String namespace;
    ClusterConnection cluster;
    
    boolean patchAmq;
    
    public Updater(ClusterConnection cluster,String namespace,String name,boolean patchAmq) {
        this.namespace = namespace;
        this.name = name;
        this.cluster = cluster;
        this.patchAmq = patchAmq;
    }

    public void rollout() throws Exception {
        String deploymentURI = "/apis/apps/v1/namespaces/" + this.namespace + "/deployments/openunison-" + this.name;
        WsResponse resp = this.cluster.get(deploymentURI);
        if (resp.getResult() != 200) {
            throw new Exception("Could not load " + deploymentURI + " / " + resp.getResult() + " / " + resp.getBody().toString());
        } else {
            io.k8s.obj.IoK8sApiAppsV1Deployment deployment = io.k8s.JSON.getGson().fromJson(resp.getBody().toJSONString(), io.k8s.obj.IoK8sApiAppsV1Deployment.class);
            io.k8s.obj.IoK8sApiAppsV1Deployment patch = new io.k8s.obj.IoK8sApiAppsV1Deployment();
            patch.setMetadata(new IoK8sApimachineryPkgApisMetaV1ObjectMeta());
            patch.setSpec(deployment.getSpec());

            if (patch.getSpec().getTemplate().getMetadata().getAnnotations() == null) {
                patch.getSpec().getTemplate().getMetadata().setAnnotations(new HashMap<String,String>());
            }

            patch.getSpec().getTemplate().getMetadata().getAnnotations().put("tremolo.io/update", new DateTime().toString());
            
            resp = this.cluster.patch(deploymentURI, patch.toJson());
            if (resp.getResult() < 200 || resp.getResult() > 299) {
                throw new Exception("Could not patch " + deploymentURI + " / " + resp.getResult() + " / " + resp.getBody().toString());
            } else {
                System.out.println("Patched " + deploymentURI);
            }

        }

        if (patchAmq) {
            deploymentURI = "/apis/apps/v1/namespaces/" + this.namespace + "/deployments/amq-" + this.name;
            resp = this.cluster.get(deploymentURI);
            if (resp.getResult() != 200) {
                throw new Exception("Could not load " + deploymentURI + " / " + resp.getResult() + " / " + resp.getBody().toString());
            } else {
                io.k8s.obj.IoK8sApiAppsV1Deployment deployment = io.k8s.JSON.getGson().fromJson(resp.getBody().toJSONString(), io.k8s.obj.IoK8sApiAppsV1Deployment.class);
                io.k8s.obj.IoK8sApiAppsV1Deployment patch = new io.k8s.obj.IoK8sApiAppsV1Deployment();
                patch.setMetadata(new IoK8sApimachineryPkgApisMetaV1ObjectMeta());
                patch.setSpec(deployment.getSpec());

                if (patch.getSpec().getTemplate().getMetadata().getAnnotations() == null) {
                    patch.getSpec().getTemplate().getMetadata().setAnnotations(new HashMap<String,String>());
                }

                patch.getSpec().getTemplate().getMetadata().getAnnotations().put("tremolo.io/update", new DateTime().toString());
                
                resp = this.cluster.patch(deploymentURI, patch.toJson());
                if (resp.getResult() < 200 || resp.getResult() > 299) {
                    throw new Exception("Could not patch " + deploymentURI + " / " + resp.getResult() + " / " + resp.getBody().toString());
                } else {
                    System.out.println("Patched " + deploymentURI);
                }

            }   
        }


        

        
    }

    
}
