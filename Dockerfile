FROM eclipse-temurin:17-jre

WORKDIR /app

COPY .redkite-docker/classes /app/classes
COPY .redkite-docker/lib/postgresql.jar /app/lib/postgresql.jar

EXPOSE 6502

CMD ["sh", "-c", "java -cp /app/classes:/app/lib/postgresql.jar -Dredkite.db.url=jdbc:postgresql://postgres:5432/redkite -Dredkite.db.user=redkite -Dredkite.db.password=redkite -Dredkite.port=6502 com.redkite.server.RedKiteServerMain"]
