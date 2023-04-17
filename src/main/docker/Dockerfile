FROM ubuntu:22.04

MAINTAINER Tremolo Security, Inc. - Docker <docker@tremolosecurity.com>

RUN apt-get update;apt-get -y install openjdk-17-jre-headless curl apt-transport-https gnupg && \
    curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
    groupadd -r ouoperator -g 433 && \
    mkdir /usr/local/ouoperator && \
    useradd -u 431 -r -g ouoperator -d /usr/local/ouoperator -s /sbin/nologin -c "OpenUnison Operator Docker image user" ouoperator && \
    chown -R ouoperator:ouoperator /usr/local/ouoperator 

ADD target/operator-*.jar /usr/local/ouoperator/ouoperator.jar

USER 431

CMD ["/usr/bin/java", "-jar", "/usr/local/ouoperator/ouoperator.jar"]
