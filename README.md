# Enum-AD

## Find Delegation

### Impacket
```
python3 findDelegation.py -hashes <:hash> FQDN/user -dc-ip <ip>
```
### Pywerview 
```
pywerview get-netuser -u cturpin --hashes 8432ec4c4f9b9ce96b73a6451a1d9dcc -d telecorp.local -t DC-01 --dc-ip 10.10.50.15 --unconstrained
```
