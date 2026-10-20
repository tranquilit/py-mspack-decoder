# py-mspack-decoder

Pure-Python decoder for Microsoft Kerberos PAC structures, including compressed claims (LZNT1, XPRESS and XPRESS Huffman). No third-party dependencies for PAC **decoding**.

**AI-assisted development:** Most of the implementation was written with AI coding tools under human direction. It has not undergone an independent security audit.



## Minimal Flask + Kerberos example

See [examples/flask_gssapi.py](examples/flask_gssapi.py). It accepts an HTTP `Authorization: Negotiate` token using the service keytab, obtains a completed **Kerberos acceptor** context, and calls:

```python
from pac_decoder.gssapi_helpers import decode_completed_context

pac_info = decode_completed_context(ctx)
print(pac_info["sid"], pac_info["groups"])
```

The helper requires a completed Kerberos acceptor context and exactly one `urn:mspac:` attribute flagged `authenticated` and `complete` by GSSAPI. It then strictly decodes the PAC. The underlying GSSAPI/Kerberos implementation, **not this package**, verifies PAC authenticity; successful authentication alone is not enough if the authenticated PAC attribute is missing.

### Run the example

The server must have a valid `HTTP/<hostname>@REALM` principal in its keytab, and MIT Kerberos must support the authenticated `urn:mspac:` attribute.

```bash
export KRB5_KTNAME=/path/to/http.keytab
export KERBEROS_HOSTNAME=service.example.com
flask --app examples/flask_gssapi.py run --host 127.0.0.1
```

From a Kerberos-authenticated client, over your HTTPS reverse proxy:

```bash
curl --negotiate -u : https://service.example.com/pac
```

This is intentionally a **one-round-trip Kerberos HTTP** example. It rejects negotiations needing several GSSAPI exchanges instead of attempting to resume a lost context. Use TLS, a trusted reverse proxy and a production WSGI server for a real service. The endpoint returns identity information only as a demonstration; do not expose it publicly. PAC group membership reflects ticket issuance time, not necessarily current AD state.

## License

MIT. See [LICENSE](LICENSE).
