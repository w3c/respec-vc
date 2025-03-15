# Verifiable Credentials for ReSpec

This ReSpec extension enhances the
[Verifiable Credential](https://www.w3.org/TR/vc-data-model/)
examples in your specification.

The [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
extension to the [ReSpec](https://respec.org/docs/#abstract)
document authoring environment enables authors to express simple
examples of [credentials](https://www.w3.org/TR/vc-data-model/#abstract)
in their specification which are then enhanced by this extension to
show the digitally signed forms of the credential. An example of the
output of this extension is provided below (this extension adds the
tabs seen in the image below):

![image](https://github.com/w3c/respec-vc/assets/108611/0c32d83a-fd32-48fa-9c35-6eb2cea20af5)

This extension can also be used to generate human-readable cryptographic hashes
of files that are retrievable by a browser environment.

# Usage

To use this extension, include the following line in your ReSpec file:

```html
<script class="remove" src="https://cdn.jsdelivr.net/gh/w3c/respec-vc@3.3.5/dist/main.js"></script>
```

Note that there might be releases later than the one listed above.
Check this repository's [tags](https://github.com/digitalbazaar/respec-vc/tags)
for all known releases.

# Generate Verifiable Credential Examples

To use this extension, you must add the `vc` class to your examples.

## Options

### Set Specific Tabs to Display

The `data-vc-tabs` property can be set to a space-delimited list containing any
of the following values to customize the tabs displayed:

On by default:
* `ecdsa-rdfc-2019` - https://www.w3.org/TR/vc-di-ecdsa/
* `eddsa-rdfc-2022` - https://www.w3.org/TR/vc-di-eddsa/
* `ecdsa-sd-2023` - https://www.w3.org/TR/vc-di-ecdsa/
* `bbs-2023`  - https://www.w3.org/TR/vc-di-bbs/
* `jose` - https://w3c.github.io/vc-jose-cose/#with-jose

Optional:
* `cbor-ld` - https://json-ld.github.io/cbor-ld-spec/
* `qr` - https://w3c-ccg.github.io/vc-barcodes/
* `Ed25519Signature2020` - https://www.w3.org/TR/vc-di-eddsa/#the-ed25519signature2020-suite
* `sd-jwt` - https://www.w3.org/TR/vc-jose-cose/#with-sd-jwt
* `cose` - https://www.w3.org/TR/vc-jose-cose/#securing-with-cose

```html
<pre class="example nohighlight vc" title="Usage of the id property"
  data-vc-tabs="bbs-2023 vc-jwt">
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  <span class="highlight">"id": "http://example.edu/credentials/3732"</span>,
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": "https://example.edu/issuers/565049",
  "issuanceDate": "2010-01-01T00:00:00Z",
  "credentialSubject": {
    <span class="highlight">"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"</span>,
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  }
}
</pre>

### Set Verification Method

The `data-vc-vm` option can be used to provide a digital proof verification
method (e.g., a URL to a public key):

```html
<pre class="example nohighlight vc" title="Usage of the id property"
  data-vc-vm="https://example.edu/issuers/565049#key-1">
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  <span class="highlight">"id": "http://example.edu/credentials/3732"</span>,
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": "https://example.edu/issuers/565049",
  "issuanceDate": "2010-01-01T00:00:00Z",
  "credentialSubject": {
    <span class="highlight">"id": "did:example:ebfeb1f712ebc6f1c276e12ec21"</span>,
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  }
}
</pre>
```

# Generate Binary VCs and QR Codes

It is possible to use semantic compression to highly compress VCs to 
compact binary representations as small as 185 bytes. You can do 
so by using the 'cbor-ld` option in `data-vc-tabs`. The output
will look like the following:

![image](https://github.com/user-attachments/assets/821c6841-f7db-44e4-99d6-132918fc5b1e)

It is also possible to represent these binary representations using QR Codes.
You can show a QR Code encoding of a VC by using the `qr` option in 
`data-vc-tabs`:

![image](https://github.com/user-attachments/assets/19259b8c-c193-486b-a0c3-f13fd0aba1e4)

# Generate Cryptographic Hashes

To use this extension, you must add the `vc-hash` class to an HTML element
such as a SPAN or DIV tag.

```html
<p>
This section demonstrates the hashing of remote files. Hashes for
`https://www.w3.org/ns/credentials/v2` are provided below:
</p>

<ul>
  <li>
raw (`openssl dgst -sha256`):
<span class="vc-hash" data-hash-url="https://www.w3.org/ns/credentials/v2"
  data-hash-format="openssl dgst -sha256" />
  </li>
  <li>
digestSRI (sha2-256 base64pad):
<span class="vc-hash" data-hash-url="https://www.w3.org/ns/credentials/v2"
  data-hash-format="sri sha2-256" />
  </li>
  <li>
digestSRI (sha2-384 base64pad):
<span class="vc-hash" data-hash-url="https://www.w3.org/ns/credentials/v2"
  data-hash-format="sri sha2-384" />
  </li>
  <li>
digestMultibase (sha2-256 base16):
<span class="vc-hash" data-hash-url="https://www.w3.org/ns/credentials/v2"
  data-hash-format="multihash sha2-256 base16" />
  </li>
  <li>
digestMultibase (sha2-256 base58btc):
<span class="vc-hash" data-hash-url="https://www.w3.org/ns/credentials/v2"
  data-hash-format="multihash sha2-256 base58btc" />
  </li>
  <li>
digestMultibase (sha2-256 base64-url-nopad):
<span class="vc-hash" data-hash-url="https://www.w3.org/ns/credentials/v2"
  data-hash-format="multihash sha2-256" />
  </li>
  <li>
digestMultibase (sha2-384 base64-url-nopad):
<span class="vc-hash" data-hash-url="https://www.w3.org/ns/credentials/v2"
  data-hash-format="multihash sha2-384" />
  </li>
  <li>
digestMultibase (sha3-256 base64-url-nopad):
<span class="vc-hash" data-hash-url="https://www.w3.org/ns/credentials/v2"
  data-hash-format="multihash sha3-256" />
  </li>
  <li>
digestMultibase (sha3-384 base64-url-nopad):
<span class="vc-hash" data-hash-url="https://www.w3.org/ns/credentials/v2"
  data-hash-format="multihash sha3-384" />
  </li>
</ul>
```

## Options

The `data-hash-url` option is used to provide the URL for which a
cryptographic digest should be generated.

The `data-hash-format` specifies various ways in which the cryptographic digest
can be expressed. The supported hash expression formats are: `openssl`, `sri`, and `multihash`. The supported digest algorithms are `sha2-256` (default), `sha2-384`, `sha3-256`, and `sha3-384`. The supported base encodings are `base64url` (default), `base64pad`, `base16`, and `base58btc`.

# Development

```sh
$ npm i
$ npm run build # build and watch index.js changes
$ npm run start # serve this directory
```

## Creating a Release

NOTE: This release process is not ideal and is planned to be changed/imporved in future.

To create a new release:

1. Clear out `node_modules/` and `dist/`
2. `git pull origin main`
3. `git checkout -b VERSION` (where `VERSION` is something like `3.3.2`)
4. `npm i`
5. `npm run build`
6. Test by running `npm run start` and ensure `index.html` loads without errors.
7. `git add -f dist/main.js && git commit -a`
6. `git tag VERSION`
7. `git push --tags`

**DO NOT merge the branch down to main.** All tagged releases are
"headless" because they contain massive 7MB files.
