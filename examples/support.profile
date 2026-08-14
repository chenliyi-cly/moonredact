max-input=200000
allow=127.0.0.1
dictionary=tenant|ACME INTERNAL|fold|700
default=mask:0
salt=support-export-v1
rule=credential|remove|900
rule=payment-card|mask:4|800
rule=ipv4|token:net_|700
