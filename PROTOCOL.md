# Roughtime protocol

## Messages

Roughtime messages are a map from uint32s to byte-strings. The number of elements in the map and the sum of the lengths of all the byte-strings are, at most, 2\*\*32-1. All the byte strings must have lengths that are a multiple of four.

All values are encoded in little-endian form because every platform that Google software runs on is little-endian.

The header of a message looks like:

```
uint32 num_tags
uint32 offsets[max(0, num_tags-1)]
uint32 tags[num_tags]
```

Following the header are the contents of the byte-strings. The first byte after the header is considered be offset zero and is the start of the value for the first tag. The `offsets` array gives the offset of the value for all tags after the first.

Tags must be in strictly ascending order and offsets must be a multiple of four. Parsers must require this.

Here are some example messages, given in hex:

The empty message consists of four, zero bytes:

```
00000000  # num_tags = 0
```

A message with a single tag (0x1020304) with value 80808080:

```
01000000  # num_tags = 1
# No offsets
04030201  # tag 0x1020304
80808080  # value starts immediately after the header
```

A message with two tags:

```
02000000  # num_tags = 2
04000000  # offset 4 for the value of the second tag
05030200  # tag 0x020305
04030201  # tag 0x1020304
00000000  # value for 0x020305 starts immediately after the header
80808080  # value for 0x1020304 starts at offset four
```

Note that the ordering of the tags is based on their numerical order, not on the lexicographic order of their encodings.

When processing messages, unknown tags are ignored.

## Tag values

Tags can be arbitrary 32-bit values but in this document they will often be written as three or four capital letters, e.g. `NONC`. In these cases, the numeric value of the tag is such that the little-endian encoding of it causes that string to be written out. So the numeric value of `NONC` is 0x434e4f4e. For three-letter tags, the last byte will be given explicitly, e.g. `SIG\x00`.

## Requests

A Roughtime request is a message with at least the tag `NONC`. The value of `NONC` is 64, arbitrary bytes that form a nonce in the protocol. Other tags must be ignored.

(The simplest clients can just generate random values for the nonce. Clients that participate in the [wider ecosystem](/ECOSYSTEM.md) generate nonces in a different way.)

Request messages sent over UDP must be at least 1024 bytes long in order to ensure that a Roughtime server cannot act as an amplifier. The canonical way to ensure this is to include a `PAD\xff` tag, whose value is an arbitrary number of zero bytes. It's expected that a UDP request contain exactly 1024 bytes as there's no point padding the request to more than the minimum.

## Responses

Responses are messages that contain at least the following tags:
  * `SREP`: signed response bytes, the value of which is itself a message.
  * `SIG\x00`: the signature, an opaque byte-string that authenticates the value of `SREP`. At the moment, Ed25519 is the only supported signature algorithm and so this will be a 64-byte value.
  * `CERT`: the server's certificate, which contains a time-limited online key authenticated by the server's long-term key.
  * `INDX` and `PATH`: the position and upwards path for this response in a Merkle tree. See the section on signatures, below.

### The signed response and Roughtime UTC.

The signed portion of a response is a message that contains the timestamp from the server as well as the root of a Merkle tree for authenticating it. It's contained in the value of the `SREP` tag.

The timestamp is expressed in two tags: `MIDP` and `RADI`. The `MIDP` tag contains a uint64 which is the midpoint, in microseconds, of a span of time, while the `RADI` tag contains the radius of that span in microseconds, expressed as a uint32. The server asserts that the true time, at the point of processing, lies within that span.

The “true time” for Roughtime is defined as being UTC with a 24-hour linear leap-second smear. That is, when a leap-second is added or removed from UTC it is smeared out over the course of a day. So UTC noon to noon on the date in question will consist of 86,399 or 86,401 SI seconds, with all the smeared seconds being the same length.

As noted, the signed response message also includes the root of a Merkle tree in a `ROOT` tag. The semantics of this are detailed in the next section.

### Authenticating replies

In order to authenticate the response and ensure freshness, the nonce provided in a request must be bound into the signed response. In order to allow a server to sign a batch of responses the nonces are built into a tree and only the root of the tree is included in the signed message.

A signature of the encoded, signed response message is included as the value of the top-level `SIG\x00` tag. This signature must be checked with respect to the online key that's included in the certificate. (See next section.)

Additionally, a client must ensure that their nonce is included the tree. To do so, the values of the `INDX` and `PATH` tags from the top-level response are needed, as well as the value of the `ROOT` tag from the signed response message.

The value of the `INDX` tag is a uint32 and specifies the position of the client's nonce in the tree. The value of the `PATH` tag is a series of hashes on the path from the client's nonce to the root of the tree. The value of the `ROOT` tag is the claimed root of the tree. The hash function used throughout is SHA-512 so the length of the root is 64 bytes and the length of the path is a multiple of 64 bytes.

A client can verify that its nonce is included in a tree using the following pseudo code:

```
index = top-level-response.getU32("INDX")
path = top-level-response.getMultipleOf64Bytes("PATH")
hash = hashLeaf(nonce-from-request)

while len(path) > 0 {
  if index&1 == 0 {
    hash = hashNode(hash, path[:64])
  } else {
    hash = hashNode(path[:64], hash)
  }

  index >>= 1
  path = path[64:]
}

if hash != signed-response-message.Get64Bytes("ROOT") {
  return error;
}

function hashLeaf(leaf) {
  return SHA-512("\x00" + leaf)
}

function hashNode(left, right) {
  return SHA-512("\x01" + left + right)
}
```

### Certificates

In order to allow a server to keep its long-term identity key offline, a response includes a ‘certificate’, which is a limited delegation from the long-term key to an online key. This certificate is contained in a message which is the value of the `CERT` tag in a response.

The certificate message contains two tags: `SIG\x00` and `DELE`. The value of the `SIG\x00` tag is a signature of the value of the `DELE` tag, made by the server's long-term key. (Clients must know the server's public key a priori.) Since Ed25519 is currently the only supported signature algorithm, this value will be 64 bytes long.

The contents of the value of the `DELE` tag are a message containing:
  * `PUBK`: the online public key. This key is used to produce the signature of the signed response message in the top-level of the response.
  * `MINT` and `MAXT`: these uint64s limit the times that the online key can authenticate. The midpoint of any time span using that key must be greater than (or equal to) the value of `MINT` and less than (or equal to) the value of `MAXT`.

### Processing a response

To summarise the above, the full structure of a response (when considering nested messages) looks like this:

  * `SREP`
    * `ROOT`
    * `MIDP`
    * `RADI`
  * `SIG\x00`
  * `INDX`
  * `PATH`
  * `CERT`
    * `SIG\x00`
    * `DELE`
      * `MINT`
      * `MAXT`
      * `PUBK`

The procedure to fully process a response results in an authenticated midpoint and radius and contains roughly these steps:
  1. Verify the signature in the certificate of the delegation message.
  1. Verify the top-level signature of the signed response message using the public key from the delegation.
  1. Verify that the nonce from the request is included in the Merkle tree.
  1. Verify that the midpoint is within the valid bounds of the delegation.
  1. Return the midpoint and radius.
