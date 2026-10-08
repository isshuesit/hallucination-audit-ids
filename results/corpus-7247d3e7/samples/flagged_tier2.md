# 20 random sentences with only Tier 2 hits (of 493)

_source: earlier run, API-default sampling, prompt v1, 63 attack-flow and 337 benign-flow explanations; not generated under freeze-1_

## 1. A031 S1 (benign-flow)

```
Destination Port: 443
Flow Duration: 115673836
Forward Packets: 29
Flow Bytes/s: 204.05
Flow Packets/s: 0.52
ACK Flag Count: 0
```

> This network flow targets destination port 443, which is commonly used for HTTPS encrypted communication.

Subtypes: port, encryption; hedged: False

## 2. A040 S3 (attack-flow)

```
Destination Port: 8899
Flow Duration: 86
Forward Packets: 1
Flow Bytes/s: 93023.26
Flow Packets/s: 23255.81
ACK Flag Count: 0
```

> This port is not commonly associated with standard well-known network services.

Subtypes: port; hedged: False

## 3. A052 S2 (benign-flow)

```
Destination Port: 53
Flow Duration: 47898
Forward Packets: 1
Flow Bytes/s: 2734.98
Flow Packets/s: 41.76
ACK Flag Count: 0
```

> Port 53 is commonly associated with DNS (Domain Name System) traffic.

Subtypes: port; hedged: False

## 4. A093 S1 (benign-flow)

```
Destination Port: 53
Flow Duration: 23598
Forward Packets: 1
Flow Bytes/s: 9407.58
Flow Packets/s: 84.75
ACK Flag Count: 0
```

> This network flow data indicates traffic destined for port 53, which is the standard port for DNS services.

Subtypes: port; hedged: False

## 5. A110 S10 (benign-flow)

```
Destination Port: 443
Flow Duration: 117223378
Forward Packets: 6
Flow Bytes/s: 2.56
Flow Packets/s: 0.09
ACK Flag Count: 1
```

> The observed pattern of minimal activity over an extended duration is an unusual characteristic for typical secure web traffic.

Subtypes: encryption; hedged: False

## 6. A131 S9 (benign-flow)

```
Destination Port: 443
Flow Duration: 42136677
Forward Packets: 2
Flow Bytes/s: 0.28
Flow Packets/s: 0.07
ACK Flag Count: 1
```

> The combination of a very long duration with minimal packet and byte activity is highly unusual for typical network traffic.

Subtypes: protocol; hedged: False

## 7. A134 S2 (benign-flow)

```
Destination Port: 80
Flow Duration: 82346387
Forward Packets: 28
Flow Bytes/s: 609.61
Flow Packets/s: 0.69
ACK Flag Count: 0
```

> The flow targets destination port 80, which is commonly associated with unencrypted HTTP web traffic.

Subtypes: port, encryption; hedged: False

## 8. A150 S1 (benign-flow)

```
Destination Port: 53
Flow Duration: 346
Forward Packets: 2
Flow Bytes/s: 820809.25
Flow Packets/s: 11560.69
ACK Flag Count: 0
```

> This network flow targets destination port 53, which is commonly associated with DNS services.

Subtypes: port; hedged: False

## 9. A174 S3 (benign-flow)

```
Destination Port: 53
Flow Duration: 241
Forward Packets: 2
Flow Bytes/s: 1751037.34
Flow Packets/s: 16597.51
ACK Flag Count: 0
```

> Port 53 is conventionally used for the Domain Name System (DNS) services.

Subtypes: port; hedged: False

## 10. A198 S1 (benign-flow)

```
Destination Port: 443
Flow Duration: 162042
Forward Packets: 8
Flow Bytes/s: 26937.46
Flow Packets/s: 74.05
ACK Flag Count: 0
```

> This network flow targets destination port 443, commonly associated with HTTPS traffic.

Subtypes: port; hedged: False

## 11. A251 S1 (attack-flow)

```
Destination Port: 80
Flow Duration: 98329876
Forward Packets: 7
Flow Bytes/s: 121.71
Flow Packets/s: 0.13
ACK Flag Count: 1
```

> This network flow is directed to destination port 80, which typically serves unencrypted web traffic.

Subtypes: encryption; hedged: False

## 12. A262 S2 (benign-flow)

```
Destination Port: 8479
Flow Duration: 47
Forward Packets: 1
Flow Bytes/s: 255319.15
Flow Packets/s: 42553.19
ACK Flag Count: 1
```

> The communication targeted destination port 8479, which is a non-standard port not typically associated with common services.

Subtypes: port; hedged: False

## 13. A274 S1 (benign-flow)

```
Destination Port: 443
Flow Duration: 4754228
Forward Packets: 10
Flow Bytes/s: 978.71
Flow Packets/s: 4.21
ACK Flag Count: 0
```

> This network flow targeted destination port 443, which is commonly used for secure web traffic (HTTPS).

Subtypes: port, encryption; hedged: False

## 14. A288 S2 (benign-flow)

```
Destination Port: 53
Flow Duration: 107724
Forward Packets: 1
Flow Bytes/s: 1763.77
Flow Packets/s: 18.57
ACK Flag Count: 0
```

> The flow targeted destination port 53, which is commonly associated with DNS services.

Subtypes: port; hedged: False

## 15. A298 S2 (benign-flow)

```
Destination Port: 443
Flow Duration: 244317
Forward Packets: 8
Flow Bytes/s: 18291.81
Flow Packets/s: 77.77
ACK Flag Count: 0
```

> Port 443 is typically associated with secure HTTPS communication.

Subtypes: port; hedged: False

## 16. A302 S8 (benign-flow)

```
Destination Port: 443
Flow Duration: 5873308
Forward Packets: 9
Flow Bytes/s: 638.65
Flow Packets/s: 2.38
ACK Flag Count: 0
```

> The absence of ACK flags is also unusual for a standard connection to port 443.

Subtypes: protocol; hedged: False

## 17. A317 S2 (benign-flow)

```
Destination Port: 53
Flow Duration: 31073
Forward Packets: 2
Flow Bytes/s: 8431.76
Flow Packets/s: 128.73
ACK Flag Count: 0
```

> The observed network flow is directed to destination port 53, which is primarily used for DNS (Domain Name System) services.

Subtypes: port; hedged: False

## 18. A342 S11 (attack-flow)

```
Destination Port: 80
Flow Duration: 1116165
Forward Packets: 3
Flow Bytes/s: 10422.29
Flow Packets/s: 8.06
ACK Flag Count: 0
```

> Collectively, these characteristics suggest the observed network flow deviates significantly from normal web traffic and warrants further security investigation.

Subtypes: protocol, baseline; hedged: True

## 19. A369 S7 (benign-flow)

```
Destination Port: 443
Flow Duration: 4132007
Forward Packets: 5
Flow Bytes/s: 53.48
Flow Packets/s: 1.69
ACK Flag Count: 1
```

> This combination of a long-lived connection with extremely low packet and byte counts is unusual for standard HTTPS activity.

Subtypes: baseline; hedged: False

## 20. A375 S1 (attack-flow)

```
Destination Port: 80
Flow Duration: 98755278
Forward Packets: 8
Flow Bytes/s: 120.66
Flow Packets/s: 0.14
ACK Flag Count: 1
```

> This network flow targets destination port 80, which is commonly used for unencrypted web communication.

Subtypes: port, encryption; hedged: False

