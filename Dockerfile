ARG keycloak_version=21.0.0

FROM quay.io/keycloak/keycloak:${keycloak_version}

ARG keycloak_version=21.0.0

## copy jar
COPY target/keycloak-justauth-${keycloak_version}-jar-with-dependencies.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build
