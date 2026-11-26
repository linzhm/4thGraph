"""Use synthetic native P2PK and P2PKH payments as benchmark controls."""
from fourthgraph.benchmark.cases import Template, native_coin

TEMPLATES = {"p2pk": Template(lambda label, value: native_coin(label, value, p2pk=True)),
             "p2pkh": Template(native_coin)}
