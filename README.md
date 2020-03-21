# Roughtime

Roughtime is a project that aims to provide secure time synchronisation.

  * [BUILDING.md](/BUILDING.md): how to build the Roughtime sources.
  * [PROTOCOL.md](/PROTOCOL.md): details of the protocol.
  * [ECOSYSTEM.md](/ECOSYSTEM.md): wider implementation concerns.
  * [CONTRIBUTING.md](/CONTRIBUTING.md): how to contribute to Roughtime.

Roughtime is discussed on the [mailing list](https://groups.google.com/a/chromium.org/forum/#!forum/proto-roughtime).

## Secure, rough time.

One often needs to ensure that information is “fresh” in secure protocols: certificates need to be current, software updates need to return the latest version etc. There are essentially only two ways to achieve this: nonces or synchronised clocks.

Nonces are large, random numbers that are included in a request. Any subsequent reply has to integrate the nonce somehow to link it to the request; usually by signing it. Since the space of nonces is so vast, we can assume that they'll never be reused. Thus a reply that incorporates a nonce must have been generated after the request that triggered it.

Nonces are inherently interactive. To ensure freshness without interaction we can use synchronised clocks and expiry times. If the “current” time is before the (signed) expiry time then the information can be considered fresh. This is so useful that it pops up all over the place. Certificates obviously have expiration times, but so do OCSP responses, Kerberos tickets, DNSSEC replies and PGP keys. Chrome's built-in certificate pins have an expiry time in the Chrome binary.

So lots of security properties depend on knowing the correct time, but that assumption is used to a far greater extent than the reality of time synchronisation warrants.

NTP is the dominant protocol used for time synchronisation and, although recent versions provide for the possibility of authentication, in practice that's not used. Most computers will trust an unauthenticated NTP reply to set the system clock meaning that a MITM attacker can control a victim's clock and, probably, violate the security properties of some of the protocols listed above. Existing defenses against this are generally heuristic: for example, Windows won't accept an NTP reply that moves the clock more than 15 hours and will typically only synchronise once every nine hours.

Mobile phones might be a little better as they often get their time from their cellular network. However, as numerous researchers keep showing, cellular network security isn't a good as we would like it to be either.

## So, secure NTP?

The obvious answer to this problem is to authenticate NTP replies. Indeed, if you want to do this there's [NTPv4 Autokey](https://tools.ietf.org/html/rfc5906) from six years ago and [NTS](https://tools.ietf.org/html/draft-ietf-ntp-network-time-security-14), which is in development. [A paper](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/dowling) at USENIX Security this year detailed how to do it so that it's stateless at the server and still mostly using fast, symmetric cryptography.

But that's what NTP *should* have been, 15 years ago—it just allows the network to be untrusted. We aim higher these days.

## Roughtime

Roughtime is a protocol that aims to achieve rough time synchronisation in a secure way that doesn't depend on any particular time server, and in such a way that, if a time server does misbehave, clients end up with cryptographic proof of it.

“Rough” time synchronisation means that, at this stage, we would be happy with time synchronisation to within 10 seconds of the correct time. If you have *serious* time synchronisation needs you'll want the [machinery in NTP](https://www.eecis.udel.edu/~mills/ntp/html/discipline.html) or even [PTP](https://en.wikipedia.org/wiki/Precision_Time_Protocol) (which needs hardware support to do right). There's no reason why Roughtime shouldn't be (almost) as precise as NTP, but the use cases that we have in mind for now don't need much precision. For example, about 25% of certificate errors shown by Chrome appear to be caused by bad local clocks and we don't need much precision to fix that.

The word “secure” means that Roughtime servers sign every reply. That sounds a lot like the various secure NTP schemes, but the difference is that they negotiate a symmetric key (or hash value) with their clients, while Roughtime uses a public-key signature for every reply. (We'll get back to how to do that quickly.)

A public-key signature can be verified by anyone as coming from the server, as opposed to a symmetric signature which can be created by either the client or the server. This means that Roughtime replies can be used as a time-stamping service, and thus that Roughtime servers can be used to check each other.

The design looks like this: a completely fresh client generates a random nonce and sends it to a Roughtime server. The reply from the server includes the current time, the client's nonce, and a signature of them both. If the server is completely trusted, the client can stop there: it knows that the reply from the server is fresh because it includes the nonce that the client generated. It knows that it's authentic because it has a signature from the server. But if it doesn't completely trust the server it can ask another for the time:

For the second request, the client generates its nonce by hashing the reply from the first server with a random value. This proves that the nonce was created after the reply from the first server. It sends that to the second server and receives a signature from it covering that nonce and the time from the second server. Let's assume that the times from the two servers are significantly different. If the time from the server second server is before the first, then the client has proof of misbehaviour: the reply from the second server implicitly shows that it was created later because of the way that the client constructed the nonce. If the time from the second server is after, then the client can contact the first server again and get a signature that was provably created afterwards, but with an earlier timestamp.

With only two servers, the client can end up with proof that something is wrong, but no idea what the correct time is. But with half a dozen or more independent servers, the client will end up with chain of proof of any server's misbehaviour, signed by several others, and (presumably) enough accurate replies to establish what the correct time is.

We envision that clients will maintain a rolling window of signature chains and will be able to upload any proofs of misbehaviour.

## Signing many requests

The reason that secure NTP protocols have tried to use symmetric cryptography wherever possible is because it's much faster. As a server, having to do public-key signing on demand is daunting, especially when those demands come from UDP packets with spoofable source IP addresses. But, with a couple of key tools, we believe that it's quite viable. Firstly, elliptic-curve signature schemes can be very fast and, secondly, it's possible to sign requests in batches.

According to [SUPERCOP](http://bench.cr.yp.to/results-sign.html), a Skylake chip can do an Ed25519 signature in 48,898 cycles. At 3.3GHz, that's 67,000 signatures per second, <i>per core</i>. Additionally, we can batch a number of requests together and sign all the nonces with a single signature by building a [Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree) of them and signing the root. Under light load, each signature might only cover a single nonce but, if overloaded, the sizes of the batches can be allowed to increase. If batches of 64 requests are allowed then a Skylake chip can sign 4.3 million requests per core-second.

At that rate, the CPU time for public-key signatures becomes insignificant compared to the work needed to handle that number of packets. Since we require that requests be padded to 1KB to avoid becoming a DDoS amplifier, a 10Gbps network link could only deliver 1.2 million requests per second anyway.

It is the case that the signature, even assuming one request per batch, will add some number of microseconds of latency to the reply. Roughtime is not going to displace PTP for people who care about microseconds.

## Current state of the project

We currently provide implementations of the core of the protocol in both C++ and Go. The C++ code also includes a simple client (which doesn't implement [ecosystem](/ECOSYSTEM.md) features) and a simple server (which doesn't do things like automatic certificate rotation.)

The Go code includes a simple server and much more complete client implementation that can query multiple servers and maintain a reply chain.

(Note that the clients don't actually set the system clock yet because this is still experimental.)

Google currently operates a public Roughtime server, although without any uptime assurances.

Google has need of a secure time protocol in some of its products. At the moment we use [tlsdate](https://github.com/ioerror/tlsdate) in some cases but that is incompatible with TLS 1.3. We are testing the waters with this release of Roughtime to see whether there exists sufficient interest in the wider community to justify building an ecosystem around it. Although Roughtime can work in the case where a client simply trusts a single, specific server it's not the optimal design for that problem.

We would be interested in (either privately or via the [mailing list](https://groups.google.com/a/chromium.org/forum/#!forum/proto-roughtime)):
   * Expressions of interest relating to sizable clients.
   * Expressions of interest in running high-availibility servers.
   * Any external monitoring tools.
   * Perhaps a time-sync daemon.
