# The PAAT API (v1, read-only)

Every later GUI write will go through this API. This phase only adds
the read-only slice, so you can inspect customers and change sets
without using the HTML pages.

## Auth

- Sign in to the GUI first and reuse the `panlab_session` cookie, or
- Pass `Authorization: Bearer <token>`.

A token has the same permissions and customer scope as the user it was
created for. The plaintext value is shown once. Only a hash is stored,
in `PAAT_API_TOKENS_FILE` (default `/etc/paat/api-tokens.yaml`).
Revoking a token does not disable the person.

Create a token on the PAAT server (the file path must be writable by the
service account):

```python
from pathlib import Path
from panlab.web import tokens
print(tokens.create_token("alice", label="laptop"))
```

Do not commit tokens or put them in tickets.

## Endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/health` | none |
| GET | `/api/v1/openapi.json` | none |
| GET | `/api/v1/me` | signed in |
| GET | `/api/v1/customers` | `view` |
| GET | `/api/v1/customers/{name}/changesets` | `view`, and the customer in scope |
| GET | `/api/v1/customers/{name}/changesets/{stem}` | same, returns the change set and a blast-radius summary |
| GET | `/api/v1/customers/{name}/changesets/{stem}/plan` | same, returns the Markdown plan |

A missing permission or an out-of-scope customer returns 403. A missing
change set returns 404. Responses are JSON. No config XML and no
secrets are included in the blast-radius or `/me` bodies.

The OpenAPI document is `/api/v1/openapi.json`.
