# EXAMPLE ONLY — install under a deployment-private path if used.
# Assumes the Keycloak/BFF ingress profile is X-Forwarded-*.

# The proxy OWNS these values. Never append browser-supplied values.
proxy_set_header X-Forwarded-For   $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
proxy_set_header X-Forwarded-Port  $server_port;

# Strip other externally supplied proxy/identity metadata.
proxy_set_header Forwarded "";
proxy_set_header X-Forwarded-Prefix "";
proxy_set_header X-Original-Forwarded-For "";
proxy_set_header X-Real-IP "";
proxy_set_header X-Original-URL "";
proxy_set_header X-Original-Method "";
proxy_set_header X-Forwarded-Access-Token "";

# Strip untrusted distributed tracing/baggage by default.
proxy_set_header traceparent "";
proxy_set_header tracestate "";
proxy_set_header baggage "";
proxy_set_header b3 "";
proxy_set_header x-b3-traceid "";
proxy_set_header x-b3-spanid "";
proxy_set_header x-b3-parentspanid "";
proxy_set_header x-b3-sampled "";
proxy_set_header x-b3-flags "";
proxy_set_header uber-trace-id "";
proxy_set_header x-ot-span-context "";
