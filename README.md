# gokeyless

## What is this?
Experiment/proof of concept of a "keyless" tls client proxying requests to an unsecured server

#### keyless-client
Terminates tls connections and proxies them to keyless-target.
Uses keyless signer to generate signatures for tls handshake.

#### keyless-signer
Generates certificates and keys, signs request payload with private key matching KID.

#### keyless-target
bare bones http server used as the default proxy target


## Jank/issues?

#### proxy code in keyless-client
the proxy handling code is pretty rough as it uses net.Listener / net.Conn instead of httputil.ReverseProxy or similar
mechanisms. The reason for doing it this way is to enable proxying or arbitrary tcp connections instead of just http(s).
This way it _should_ be able to handle other protocols as well (not tested).

#### code style all over the place / general lack of polish / missing error handling / missing tests / code quality
This was an experiment made for testing some stuff out, not anything "production-grade" by any means. I probably won't
fix these issues, but feel free to fork, copy or whatever if you find anything here useful.

#### "I ran your code and something is broken"
This code is barely tested (manually) and lacks automated tests so that is unfortunately not all that surprising.
If you manage to figure it out and fix I'll be happy to look at a pr, but I probably won't spend much more time on this
repo.
