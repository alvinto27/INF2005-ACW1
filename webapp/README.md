# Local web application scaffold

This Flask scaffold wires the existing `payload_protocol.py` cryptographic
module to PNG and PCM/WAV LSB carriers.

## Run locally

```sh
python -m pip install -r requirements.txt
python -m webapp.app
```

Open <http://127.0.0.1:5000>. `/encode` accepts a multipart `file`, `team_id`,
`sender`, and `lsb` (1–8). It returns a downloadable stego PNG/WAV. `/decode`
accepts the stego file and `lsb`, extracts the packet, and returns JSON with the
verdict and payload.

The key pair is generated in memory when the process starts. Persist and rotate
keys, add authentication, and add cover-hash verification before deployment.

## Planned modules

| Module | Responsibility |
| --- | --- |
| `crypto_service.py` | OOP facade over payload creation and RSA signatures |
| `lsb.py` | Shared 1–8 LSB bit packing |
| `media.py` | PNG and PCM/WAV adapters |
| `start_location.py` | Repeatable non-zero start-unit derivation |
| `routes.py` | `/encode`, `/decode`, and GUI routing |
