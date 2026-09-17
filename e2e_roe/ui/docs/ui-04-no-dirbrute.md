# Rules of Engagement

Client: Acme Retail Ltd.

## Prohibited techniques

**Directory and file brute forcing is forbidden.** Do not use content discovery
by wordlist against any host in scope. The application logs every 404 and the
noise triggers the on-call rotation.

Crawling links that the application itself exposes is permitted.
