FROM alpine:3.19
# Positive fixture for dockerfile-add-instead-of-copy (same idea as iac_rules_configuration_jeff add_instead_of_copy/test/positive.dockerfile).
# The first ADD source must not contain ".tar" or ".tar." (see query.rego), so we use a build-arg path, not a .tar.gz URL.
# USER avoids dockerfile-missing-user-instruction so you can focus on platform exclusion for the ADD rule.
# Use with code-security.datadog.yaml v1.3 ignore-platforms / only-platforms (platform key: Dockerfile).
ARG JAR_FILE=app.jar
RUN echo "fixture"
ADD ${JAR_FILE} /app.jar
USER 65534:65534
