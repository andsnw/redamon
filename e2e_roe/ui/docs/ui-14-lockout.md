# Rules of Engagement

Client: Northwind Trading.

## Authentication testing

Techniques that can lock a real user account out are **forbidden**. The identity
provider locks an account after three failed attempts and unlocking requires a
helpdesk call, so any credential attack risks a real person losing access.

Testing a single credential per account is acceptable. Repeated attempts against
the same account are not.
