FROM websphere-liberty:beta
RUN installUtility install  --acceptLicense defaultServer
COPY server.xml /config/server.xml
COPY jvm.options /config/jvm.options
COPY target/customerservice-java-2.0.0-SNAPSHOT.war /config/apps/

ENV MONGO_HOST=customer-db
