MWLID demo showcasing namespaces in MWLID
- global LB - namespace: lb
- backend - namespace: app
Both use the same CAS Priavte Pool - therefore are in the same Trust Domain

Caveat: You may need to rerun "terraform apply" due to bug/inconsistency after first run