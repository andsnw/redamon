# Bug Bounty Program Terms — Northwind Public Program

Northwind Trading operates a public bug bounty program. These terms bind every
researcher and every automated agent acting on a researcher's behalf.

## Rate

Automated testing must not exceed **5 requests per second** in aggregate across
all tools. Programs that exceed this are rate-limited at the edge and repeated
breaches end program access.

## Identification

Every request must carry the header `X-Bug-Bounty: northwind-research` so our
operations team can attribute the traffic.

## Estate

The systems in scope are **not owned by the researcher**. This is a third-party
engagement and must be recorded as one.
