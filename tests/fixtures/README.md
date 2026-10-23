# Synthetic verification fixtures

The platform certificate and matching RSA key in this directory were generated
only for offline unit tests. They are not merchant or WeChat credentials and
must never be used in a deployed service. The certificate serial is deliberately
synthetic. The tests generate a separate current public key in memory.
