# Rules of Engagement — Globex Payments

## Window

Testing is permitted **Saturday and Sunday only**, 02:00 to 08:00, timezone
**America/New_York**. Weekday testing collides with settlement runs.

## Never touch

- `card-vault.globex.test` — holds cardholder data, out of scope entirely
- `sso.globex.test` — a lockout here locks out the whole estate

## Rate

Maximum **2 requests per second**.
