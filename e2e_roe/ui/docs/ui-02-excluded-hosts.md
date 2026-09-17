# Rules of Engagement

Client: Acme Retail Ltd.

## Hosts that must never be touched

The following hosts are inside the target domain but are explicitly OUT of scope
and must never be scanned, probed or tested:

- pay.acme.test - operated by a third-party payment processor, not Acme
- sso.acme.test - shared identity provider used by other tenants

Contacting either host would involve a third party who has not authorised this
engagement.
