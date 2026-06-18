FROM eclipse-temurin:17-jre

WORKDIR /app

COPY .redkite-docker/classes /app/classes
COPY .redkite-docker/lib/h2.jar /app/lib/h2.jar

RUN mkdir -p /app/data

EXPOSE 6502

CMD ["java", "-cp", "/app/classes:/app/lib/h2.jar", \
     "-Dredkite.db.url=jdbc:h2:./data/redkite;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE", \
     "-Dredkite.db.user=sa", \
     "-Dredkite.db.password=", \
     "-Dredkite.port=6502", \
     "com.redkite.server.RedKiteServerMain"]
