# JWKS Server

A small Flask server that publishes RSA public keys as a JWKS and issues signed
JWTs. Built for Project 1 (JWKS server).

## How it works

- On startup the server generates two RSA-2048 key pairs, each with a random `kid`:
  one that is valid for an hour and one that is already expired.
- `GET /.well-known/jwks.json` returns only the **unexpired** public key(s).
- `POST /auth` returns a JWT (RS256) signed with the valid key. The `kid` is in
  the JWT header. If the `expired` query parameter is present
  (`POST /auth?expired`), it signs with the expired key and sets `exp` in the past.
- Any other method on those routes gets a `405`.

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask app and the two endpoints |
| `keys.py` | Key generation, expiry check, JWK conversion |
| `tests/` | pytest test suite |

## Setup and run

```
pip install -r requirements.txt
python app.py
```

The server listens on http://localhost:8080.

## Tests and lint

```
python -m pytest --cov=. --cov-report=term-missing
python -m flake8 .
```
## AI usage

AI (Claude) was used on this project. See [AI_USAGE.md](AI_USAGE.md) for the
acknowledgement and the list of prompts.

## Screenshots

- `screenshots/test_client.png` - the course test client running against the server
- `screenshots/coverage.png` - pytest coverage report
