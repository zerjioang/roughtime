# Roughtime Ecosystem

The [protocol](/PROTOCOL.md) document specifies the nuts and bolts of how to query a Roughtime server but more structure is needed in order to use Roughtime fully.

## Chaining requests

As explained in the [introduction](/README.md), once there are multiple Roughtime servers a client can query several of them. If one of them provides a bogus answer then the replies of later servers can provide proof of misbehaviour.

The way this is implemented is to form the client's nonce by hashing the response from the previous request and a random, 64-byte blinding value. Specifically, a client calculates its nonce as SHA-512(SHA-512(previous-reply) + blind). By using this construction, a client can prove that a request was created after the previous reply was received. Therefore, if the next reply contains a timestamp prior to that of the previous reply, the client would have proof of a server's misbehaviour.

(Although, in that situation, it wouldn't be possible to tell which server was misbehaving without more chained requests.)

It's envisioned that a fully operational Roughtime ecosystem would involve clients that maintain “chain files”—a chain of past requests and replies. In the event that a reply from a server is sufficiently divergent from the replies from other servers, the client would make a number of additional requests (to provide additional evidence) and then upload the chain file to an auditor. The auditor service would confirm that some misbehaviour was observed in the chain and then flag it for human analysis.

A standard, JSON-based, format for chain files is specified in `config.proto`.

## Maintaining a healthy software ecosystem

A healthy software ecosystem doesn't arise by specifying how software should behave and then assuming that implementations will do the right thing. Rather we plan on having Roughtime servers return invalid, bogus answers to a small fraction of requests. These bogus answers would contain the wrong time, but would also be invalid in another way. For example, one of the signatures might be incorrect, or the tags in the message might be in the wrong order. Client implementations that don't implement all the necessary checks would find that they get nonsense answers and, hopefully, that will be sufficient to expose bugs before they turn into a Blackhat talk.

## Curating server lists

Assuming that there ever are multiple Roughtime servers, there will be a need for a canonical list of “known good” servers. For this we envision a system similar to the one for Certificate Transparency, where candidate servers are monitored for a period of time and, if they meet the published criteria around uptime and accuracy, they will be included in the list.

We also need to ensure that we can remove servers from the list. Not just for poor timekeeping, but also because services come and go. It's a problem with NTP that some devices will hardcode NTP server addresses and assume that they'll never change. There have been enough cases of this that it has it's own [Wikipedia page](https://en.wikipedia.org/wiki/NTP_server_misuse_and_abuse).

So, instead, Roughtime is only available for products that can be updated. The server lists have an explicit expiry time in them and we will actively seek to break clients that try to use old information in order to maintain ecosystem health. At the moment changing the hostname or port of a server is the easiest way to enforce this but we expect to add a per-server id in the future that clients would need to send in order to prove to the server that they have a current server list.
