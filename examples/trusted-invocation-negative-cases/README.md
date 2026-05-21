<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Trusted Invocation Negative Cases

This example runs the full local OAN stack and validates both positive
and negative Agent-to-Agent trusted invocation cases.

Run from the repository root:

```powershell
.\examples\trusted-invocation-negative-cases\run.ps1
```

The script verifies:

- valid signed User Agent invocation succeeds
- missing proof is rejected
- invalid proof creator is rejected
- tampered request signature is rejected
- missing User Agent VC is rejected
- wrong VC subject is rejected
- tampered VC signature is rejected
- invalid VC type is rejected
- credentials not array is rejected
- mismatched `bodyHash` is rejected
- missing body is rejected
- missing bodyHash is rejected
- expired timestamp is rejected
- future timestamp is rejected
- invalid timestamp format is rejected
- timestamp without timezone is rejected
- missing caller DID is rejected
- missing target DID is rejected
- missing nonce is rejected
- missing timestamp is rejected
- missing caller DID document is rejected
- mismatched caller DID document id is rejected
- replayed nonce is rejected
- wrong target DID is rejected

