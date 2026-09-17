# Rules of Engagement

Client: Globex Industrial

## Rate

Aggregate testing rate must not exceed **10 requests per second**.

## Exclusions

**legacy.globex.test** must never be touched. It is an unsupported system due for
decommissioning and the vendor will not restore it if it falls over.

## Window

Testing is permitted **Monday to Friday, 20:00 to 06:00** in **Europe/Berlin**.
Daytime testing would collide with production order processing.

## Availability

**Denial of service testing is prohibited.**

## Depth

Exploitation is permitted to demonstrate impact. **Post-exploitation is not**:
do not pivot, persist, escalate beyond the initial foothold, or move laterally.
