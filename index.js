import * as bbs2023Cryptosuite from '@digitalbazaar/bbs-2023-cryptosuite';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as cbor2 from 'cbor2';
import * as cborld from '@digitalbazaar/cborld';
import * as didKey from '@digitalbazaar/did-method-key';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as ecdsaRdfc2019Cryptosuite from
  '@digitalbazaar/ecdsa-rdfc-2019-cryptosuite';
import * as ecdsaSd2023Cryptosuite
  from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import * as examples1Context from '@digitalbazaar/credentials-examples-context';
import * as jose from 'jose';
import * as mfHasher from 'multiformats/hashes/hasher';
import * as odrlContext from '@digitalbazaar/odrl-context';
import * as vpqr from '@digitalbazaar/vpqr';
import {base64pad, base64url} from 'multiformats/bases/base64';
import {defaultDocumentLoader, issue} from '@digitalbazaar/vc';
import {extendContextLoader, purposes} from 'jsonld-signatures';
import {getCoseHtml, getJoseHtml, getSdJwtHtml} from './src/html';
import {sha3_256, sha3_384} from '@noble/hashes/sha3';
import {base16} from 'multiformats/bases/base16';
import {base58btc} from 'multiformats/bases/base58';
import {CachedResolver} from '@digitalbazaar/did-io';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import ed25519Context from 'ed25519-signature-2020-context';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {cryptosuite as eddsaRdfc2022CryptoSuite} from
  '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import examples2Context from './contexts/credentials/examples/v2';
import {getCoseExample} from './src/cose';
import {getJoseExample} from './src/jose';
import {getSdJwtExample} from './src/sd-jwt';
import {sha256} from '@noble/hashes/sha256';
import {sha384} from '@noble/hashes/sha512';

// default types
const TAB_TYPES = [
  'ecdsa-rdfc-2019',
  'eddsa-rdfc-2022',
  'ecdsa-sd-2023',
  'bbs-2023',
  'jose',
  'sd-jwt',
  'cose',
  'cbor-ld',
  'qr'
];
// additional types: Ed25519Signature2020

// purposes used below
const {AssertionProofPurpose} = purposes;

// setup contexts used by respec-vc
const contexts = {};
for(const item of [odrlContext, ed25519Context, examples1Context]) {
  for(const [url, context] of item.contexts) {
    contexts[url] = context;
  }
}
contexts['https://www.w3.org/ns/credentials/examples/v2'] = examples2Context;

// setup static document loader
const documentLoader = extendContextLoader(async function documentLoader(url) {
  const context = contexts[url];
  if(context !== undefined) {
    return {
      contextUrl: null,
      documentUrl: url,
      document: context,
    };
  }

  // try the default document loader
  try {
    const context = await defaultDocumentLoader(url);
    return context;
  } catch(e) {
    console.log(
      'Warning: Do not load context files from the network in production. ' +
      'Developer mode: loading context URL from network:', url);
  }

  // attempt to load from network
  try {
    const response = await fetch(url);
    const document = await response.json();
    return {
      contextUrl: null,
      documentUrl: url,
      document,
    };
  } catch(e) {
    console.error('Error: Failed to retrieve', url);
  }
});

// setup resolver
const resolver = new CachedResolver();
const didKeyDriver = didKey.driver();
didKeyDriver.use({
  multibaseMultikeyHeader: 'zDna',
  fromMultibase: EcdsaMultikey.from
});
didKeyDriver.use({
  multibaseMultikeyHeader: 'z82L',
  fromMultibase: EcdsaMultikey.from
});
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519Multikey.from
});
didKeyDriver.use({
  multibaseMultikeyHeader: 'zUC7',
  fromMultibase: Bls12381Multikey.from
});
resolver.use(didKeyDriver);

async function createBBSExampleProof() {
  const key = await Bls12381Multikey.generateBbsKeyPair({
    algorithm: Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256,
  });

  const proof = new DataIntegrityProof({
    signer: key.signer(),
    cryptosuite: bbs2023Cryptosuite.createSignCryptosuite({
      mandatoryPointers: ['/issuer'],
    }),
  });

  return {
    proof,
    key,
    label: 'bbs',
  };
}

async function createEcdsaRdfc2019ExampleProof() {
  const key = await EcdsaMultikey
    .generate({curve: 'P-256'});

  // ecdsa-rdfc-2019
  const {cryptosuite: rdfcCryptosuite} = ecdsaRdfc2019Cryptosuite;
  const proof = new DataIntegrityProof({
    signer: key.signer(),
    cryptosuite: rdfcCryptosuite,
  });

  return {
    proof,
    key,
    label: 'ecdsa',
  };
}

async function createEcdsaSd2023ExampleProof() {
  const key = await EcdsaMultikey
    .generate({curve: 'P-256'});

  // ecdsa-sd-2023
  const {createSignCryptosuite} = ecdsaSd2023Cryptosuite;
  const proof = new DataIntegrityProof({
    signer: key.signer(),
    cryptosuite: createSignCryptosuite({
      mandatoryPointers: ['/issuer'],
    }),
  });

  return {
    proof,
    key,
    label: 'ecdsa-sd',
  };
}

async function createEddsaRdfc2022ExampleProof() {
  // Ed25519Signature2020
  const keyPairEd25519VerificationKey2020 = await Ed25519VerificationKey2020
    .generate();

  const key = await Ed25519Multikey
    .from(keyPairEd25519VerificationKey2020);

  // eddsa-rdfc-2022
  const proof = new DataIntegrityProof({
    signer: key.signer(),
    cryptosuite: eddsaRdfc2022CryptoSuite,
  });

  return {
    proof,
    key,
    label: 'eddsa',
  };
}

async function attachProof({credential, suite}) {
  const credentialCopy = JSON.parse(JSON.stringify(credential));
  const options = {credential: credentialCopy, suite, documentLoader};
  options.purposes = new AssertionProofPurpose();
  return issue(options);
}

function addVcExampleStyles() {
  const exampleStyles = document.createElement('style');

  const radioLabels = [...Array(TAB_TYPES.length + 1).keys()]
    .map(i => {
      const j = i + 1;
      return `.vc-tabbed [type="radio"]:nth-of-type(${j}):checked ~ .vc-tabs .vc-tab:nth-of-type(${j}) label`;
    });
  const radioSelector = [...Array(TAB_TYPES.length + 1).keys()]
    .map(i => {
      const j = i + 1;
      return `.vc-tabbed [type="radio"]:nth-of-type(${j}):checked ~ .vc-tab-content:nth-of-type(${j})`;
    });

  exampleStyles.innerHTML += `
.vc-tabbed {
  overflow-x: hidden;
  margin: 0 0;
}

.vc-tabbed [type="radio"] {
  display: none;
}

.vc-tabs {
  display: flex;
  align-items: stretch;
  list-style: none;
  padding: 0;
  border-bottom: 1px solid #ccc;
}

li.vc-tab {
  margin: unset;
}

.vc-tab > label {
  display: block;
  margin-bottom: -1px;
  padding: .4em .5em;
  border: 1px solid #ccc;
  border-top-right-radius: .4em;
  border-top-left-radius: .4em;
  background: #eee;
  color: #666;
  cursor: pointer;
  transition: all 0.3s;
}

.vc-tab:hover label {
  border-left-color: #333;
  border-top-color: #333;
  border-right-color: #333;
  color: #333;
}

.vc-tab-content {
  display: none;
}
.vc-tab-content > pre {
  white-space: pre-wrap;
}

.vc-jose-cose-tabbed, .vc-jose-cose-tabbed-jwt,
.vc-jose-cose-tabbed-sd-jwt, .vc-jose-cose-tabbed-cose,
.sd-jwt-tabbed {
  overflow-x: hidden;
  margin: 0 0;
}

.vc-jose-cose-tabbed [type="radio"], .vc-jose-cose-tabbed-jwt [type="radio"],
.vc-jose-cose-tabbed-sd-jwt [type="radio"],
.vc-jose-cose-tabbed-cose [type="radio"],
.sd-jwt-tabbed [type="radio"] {
  display: none;
}

.vc-jose-cose-tabs, .vc-jose-cose-jwt-tabs, .vc-jose-cose-sd-jwt-tabs,
.vc-jose-cose-cose-tabs,
.sd-jwt-tabs {
  display: flex;
  align-items: stretch;
  list-style: none;
  padding: 0;
  border-bottom: 1px solid #ccc;
}

li.vc-jose-cose-tab, li.vc-jose-cose-jwt-tab, li.vc-jose-cose-sd-jwt-tab,
li.vc-jose-cose-cose-tab,
li.sd-jwt-tab {
  margin: 0 0;
  margin-left: 8px;
}

.vc-jose-cose-tab>label, .vc-jose-cose-jwt-tab>label,
.vc-jose-cose-sd-jwt-tab>label, .vc-jose-cose-cose-tab>label,
.sd-jwt-tab>label {
  display: block;
  margin-bottom: -1px;
  padding: .4em .5em;
  border: 1px solid #ccc;
  border-top-right-radius: .4em;
  border-top-left-radius: .4em;
  background: #eee;
  color: #666;
  cursor: pointer;
  transition: all 0.3s;
}

.vc-jose-cose-tab:hover label, .vc-jose-cose-jwt-tab:hover label,
.vc-jose-cose-sd-jwt-tab:hover label, .vc-jose-cose-cose-tab:hover label,
.sd-jwt-tab:hover label {
  border-left-color: #333;
  border-top-color: #333;
  border-right-color: #333;
  color: #333;
}

.vc-jose-cose-tab-content,
.sd-jwt-tab-content {
  display: none;
}

${radioLabels.join(',\n  ')} {
  border-bottom-color: #fff;
  background: #fff;
  color: #222;
}

${radioSelector.join(',\n  ')},
.sd-jwt-tabbed [type="radio"]:nth-of-type(1):checked ~ .sd-jwt-tab-content:nth-of-type(1),
.sd-jwt-tabbed [type="radio"]:nth-of-type(2):checked ~ .sd-jwt-tab-content:nth-of-type(2),
.sd-jwt-tabbed [type="radio"]:nth-of-type(3):checked ~ .sd-jwt-tab-content:nth-of-type(3) {
  display: block;
}

.disclosure {
  margin: 10px 0;
  font-size: 12px;
  line-height: 1.6;
  padding: 5px;
}

.disclosure h3 {
  margin: 0;
  font-size: 14px;
  padding-left: 5px;
}

.disclosure .claim-name {
  color: #333;
}

.disclosure .hash,
.disclosure .disclosure-value,
.disclosure .contents {
  color: #555;
  word-wrap: break-word;
  display: inline;
}

.disclosure p {
  margin: 0;
  padding-left: 5px;
}

.disclosure pre {
  white-space: pre-wrap;
  word-wrap: break-word;
  margin: 0;
  padding-left: 5px;
  line-height: 1.6;
  display: inline-block;
}

.header-value {
  white-space: pre-wrap;
  word-wrap: break-word;
  margin: 0;
  padding-left: 5px;
  line-height: 1.6;
  font-size: 12px;
}

.cose-text, .jose-text, .vc-jose-cose-jwt .text, .vc-jose-cose-sd-jwt .text,
 .vc-jose-cose-cose .text {
  font-family: monospace;
  color: green;
}

.sd-jwt-compact, .jwt-compact, .vc-jose-cose-jwt .compact, .vc-jose-cose-sd-jwt
 .compact, .vc-jose-cose-cose .compact {
  background-color: rgba(0,0,0,.03);
}

.sd-jwt-header, .jwt-header, .vc-jose-cose-jwt .header, .vc-jose-cose-sd-jwt
 .header, .vc-jose-cose-cose .header {
  color: red;
}

.sd-jwt-payload, .jwt-payload, .vc-jose-cose-jwt .payload, .vc-jose-cose-sd-jwt
 .payload, .vc-jose-cose-cose .payload {
  color: green;
}

.sd-jwt-signature, .jwt-signature, .vc-jose-cose-jwt .signature,
 .vc-jose-cose-sd-jwt .signature, .vc-jose-cose-cose .signature {
  color: blue;
}

.sd-jwt-disclosure, .vc-jose-cose-jwt .disclosure, .vc-jose-cose-sd-jwt
 .disclosure, .vc-jose-cose-cose .disclosure {
  color: purple;
}`;

  document.getElementsByTagName('head')[0].appendChild(exampleStyles);
}

function addContext(url, context) {
  contexts[url] = context;
}

async function createVcExamples() {
  // process all 'vc-hash' entries
  const sha2256Hasher = mfHasher.from({
    name: 'sha2-256',
    code: 0x12,
    encode: input => sha256(input),
  });
  const sha2384Hasher = mfHasher.from({
    name: 'sha2-384',
    code: 0x20,
    encode: input => sha384(input),
  });
  const sha3256Hasher = mfHasher.from({
    name: 'sha3-256',
    code: 0x16,
    encode: input => sha3_256(input),
  });
  const sha3384Hasher = mfHasher.from({
    name: 'sha3-384',
    code: 0x15,
    encode: input => sha3_384(input),
  });

  const vcHashEntries = document.querySelectorAll('.vc-hash');
  for(const hashEntry of vcHashEntries) {

    // get the hash requirements
    const hashUrl = hashEntry.dataset?.hashUrl || 'INVALID_URL';
    const hashFormat = hashEntry.dataset?.hashFormat?.split(/(\s+)/) || [];
    let encodedHash = null;

    // select the base encoder (default: base64-url with no padding)
    let baseEncoder;
    if(hashFormat.includes('sri')) {
      baseEncoder = base64pad;
    } else if(hashFormat.includes('base16')) {
      baseEncoder = base16;
    } else if(hashFormat.includes('base58btc')) {
      baseEncoder = base58btc;
    } else {
      baseEncoder = base64url;
    }

    // retrieve the file and generate the hash
    try {
      const response = await fetch(hashUrl);

      // ensure retrieval succeeded
      if(response.status !== 200) {
        throw new Error('Failed to retrieve ' + hashUrl);
      }
      const hashData = new Uint8Array(await response.arrayBuffer());

      // determine the hash algorithm to use and produce the output accordingly
      if(hashFormat.includes('openssl') && hashFormat.includes('-sha256')) {
        const mfHash = await sha2256Hasher.digest(hashData);
        encodedHash = Array.prototype.map.call(mfHash.digest, byte => {
          return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('');
      } else if(hashFormat.includes('sri')) {
        if(hashFormat.includes('sha2-256')) {
          const mfHash = await sha2256Hasher.digest(hashData);
          encodedHash = 'sha256-' + baseEncoder.encode(mfHash.digest);
        } else if(hashFormat.includes('sha2-384')) {
          const mfHash = await sha2384Hasher.digest(hashData);
          encodedHash = 'sha384-' + baseEncoder.encode(mfHash.digest);
        }
      } else if(hashFormat.includes('multihash')) {
        if(hashFormat.includes('sha2-256')) {
          const mfHash = await sha2256Hasher.digest(hashData).bytes;
          encodedHash = baseEncoder.encode(mfHash);
        } else if(hashFormat.includes('sha2-384')) {
          const mfHash = await sha2384Hasher.digest(hashData).bytes;
          encodedHash = baseEncoder.encode(mfHash);
        } else if(hashFormat.includes('sha3-256')) {
          const mfHash = await sha3256Hasher.digest(hashData).bytes;
          encodedHash = baseEncoder.encode(mfHash);
        } else if(hashFormat.includes('sha3-384')) {
          const mfHash = await sha3384Hasher.digest(hashData).bytes;
          encodedHash = baseEncoder.encode(mfHash);
        }
      }

      // set the encodedHash value
      hashEntry.innerText = encodedHash || 'Unsupported hash format: \'' +
        hashEntry.dataset?.hashFormat + '\'';
    } catch(e) {
      console.error('respec-vc error: Failed to create cryptographic hash.',
        e, hashEntry);
      hashEntry.innerText = 'Error generating cryptographic hash for ' +
        hashUrl;
    }
  }

  // process all 'did-key' entries
  const didKeyExamples = document.querySelectorAll('.did-key');
  for(const example of didKeyExamples) {
    const did = example.dataset?.did;
    try {
      const didDoc = await resolver.get({did});
      const fragmentRegex = new RegExp('\#.*"', 'g');
      const didDocJson =
        JSON.stringify(didDoc, null, 2).replaceAll(fragmentRegex, '#vm');
      example.innerText = didDocJson;
    } catch(error) {
      example.innerText = 'Failed to generate did:key example. ' +
        '(see console for details)';
      console.error('Error generating DID Document for ' + did, error);
    }
  }

  // process all 'vc' entries
  const exampleProofs = [];

  // ecdsa-rdfc-2019
  const ecdsaRdfc2019 = await createEcdsaRdfc2019ExampleProof();
  exampleProofs.push(ecdsaRdfc2019);

  // Ed25519Signature2020
  const keyPairEd25519VerificationKey2020 = await Ed25519VerificationKey2020
    .generate();
  const suiteEd25519Signature2020 = new Ed25519Signature2020({
    key: keyPairEd25519VerificationKey2020,
  });

  // eddsa-rdfc-2022
  const eddsaRdfc2022 = await createEddsaRdfc2022ExampleProof();
  exampleProofs.push(eddsaRdfc2022);

  // ecdsa-sd-2023
  const ecdsaSd2023 = await createEcdsaSd2023ExampleProof();
  exampleProofs.push(ecdsaSd2023);

  // bbs-2023
  const bbs2023 = await createBBSExampleProof();
  exampleProofs.push(bbs2023);

  // vc-jose-cose
  const jwk = await jose.generateKeyPair('ES256', {extractable: true});
  const privateKeyJwk = await jose.exportJWK(jwk.privateKey);
  privateKeyJwk.kid = 'ExHkBMW9fmbkvV266mRpuP2sUY_N_EWIN1lapUzO8ro';
  privateKeyJwk.alg = 'ES256';

  // add styles for examples
  addVcExampleStyles();

  // process every example that needs a vc-proof
  const vcExamples = document.querySelectorAll('.vc');
  let vcProofExampleIndex = 0;
  for(const example of vcExamples) {
    vcProofExampleIndex++;

    const verificationMethod = example.dataset?.vcVm ||
      'did:key:' + keyPairEd25519VerificationKey2020.publicKeyMultibase;

    const tabTypes = example.dataset?.vcTabs?.split(' ') || TAB_TYPES;

    // extract and parse the example as JSON
    let credential = {};
    try {
      let exampleText = example.innerText;
      exampleText = exampleText.replace(/\/\/ .*$/gm, '');
      credential = JSON.parse(exampleText);
    } catch(e) {
      console.error('respec-vc error: Failed to create Verifiable Credential.',
        e, example.innerText);
      continue;
    }

    // set up the tabbed content
    const tabbedContent = document.createElement('div');
    tabbedContent.setAttribute('class', 'vc-tabbed');

    // set up the tab labels
    const tabLabels = document.createElement('ul');
    tabLabels.setAttribute('class', 'vc-tabs');
    tabbedContent.appendChild(tabLabels);

    /**
     * Definition for the content callback used by addTab.
     *
     * @callback contentCallback
     */

    /**
     * Add tab to tab container in DOM. Run callback immediately.
     *
     * @param {string} suffix - One of the TAB_TYPES values (or `unsigned`).
     * @param {string} labelText - Human readable label name.
     * @param {string} tabText - Text to display on the tab.
     * @param {contentCallback} callback - Function which returns HTML.
     */
    async function addTab(suffix, labelText, tabText, callback) {
      const button = document.createElement('input');
      button.setAttribute('type', 'radio');
      button.setAttribute('id', `vc-tab${vcProofExampleIndex}${suffix}`);
      button.setAttribute('name', `vc-tabs${vcProofExampleIndex}`);
      if(tabbedContent.firstChild.tagName === 'INPUT') {
        // place this one last of the inputs
        [...tabbedContent.querySelectorAll('input')].pop().after(button);
      } else {
        tabbedContent.prepend(button);
      }

      const label = document.createElement('li');
      label.setAttribute('class', 'vc-tab');

      const tabLabel = document.createElement('label');
      tabLabel.setAttribute('for', button.getAttribute('id'));

      const abbr = document.createElement('abbr');
      abbr.setAttribute('title', labelText);
      abbr.innerText = tabText;

      tabLabel.appendChild(abbr);
      label.appendChild(tabLabel);
      tabLabels.appendChild(label);

      const content = document.createElement('div');
      content.setAttribute('class', 'vc-tab-content');
      content.style.minHeight = `${example.clientHeight}px`;
      tabbedContent.appendChild(content);

      if(suffix === 'unsigned') {
        content.innerHTML = callback();
      } else {
        content.innerHTML = await callback();
      }
    }

    /**
     * Add a Data Integrity based proof example tab.
     *
     * @global string verificationMethod
     * @param {object} suite - Suite object.
     * @param {string} tabText - Text to display on the tab.
     * @param {string | undefined} key - Optional key to use for the proof.
     */
    async function addProofTab(suite, tabText, key) {
      let verifiableCredentialProof;
      const label = suite?.cryptosuite || suite.type;

      if(key) {
        suite.verificationMethod = 'did:key:' + key.publicKeyMultibase;
      } else {
        suite.verificationMethod = verificationMethod;
      }

      await addTab(label, `Secured with Data Integrity - ${label}`, tabText, async () => {
        // attach the proof
        try {
          verifiableCredentialProof = await attachProof({credential, suite});
          const mediaType =
            (verifiableCredentialProof.type
              .includes('VerifiablePresentation')) ?
              'application/vp' : 'application/vc';
          return `<strong>${mediaType}</strong>
            <pre>${JSON.stringify(verifiableCredentialProof, null, 2)}</pre>`;
        } catch(e) {
          console.error(
            'respec-vc error: Failed to attach proof to Verifiable Credential.',
            e, example.innerText);
        }
      });
    }

    /**
     * Add a CBOR-LD example tab.
     *
     * @global string verificationMethod
     * @param {object} suite - Suite object.
     * @param {string} tabText - Text to display on the tab.
     * @param {string | undefined} key - Optional key to use for the proof.
     */
    async function addCborldTab(suite, tabText, key) {
      let verifiableCredentialProof;

      if(key) {
        suite.verificationMethod = 'did:key:' + key.publicKeyMultibase;
      } else {
        suite.verificationMethod = verificationMethod;
      }

      await addTab('Binary', `Encoded as CBOR-LD`, tabText, async () => {
        // attach the proof
        try {
          verifiableCredentialProof = await attachProof({credential, suite});
          const jsonldDiagnostic =
            JSON.stringify(verifiableCredentialProof, null, 2);
          const jsonldSize =
            JSON.stringify(verifiableCredentialProof).length;

          const cborldBytes = await cborld.encode({
            jsonldDocument: verifiableCredentialProof,
            documentLoader
          });
          const cborldSize = cborldBytes.length;
          const cborldHex = Array.from(cborldBytes, byte =>
            byte.toString(16).padStart(2, '0')).join('');
          const percentage =
            Math.floor(((jsonldSize - cborldSize) / jsonldSize) * 100);
          const cborDiagnostic = cbor2.diagnose(cborldBytes, {
            pretty: true
          });

          const mediaType =
            (verifiableCredentialProof.type
              .includes('VerifiablePresentation')) ?
              'application/vp' : 'application/vc';
          return `
            <strong>${mediaType}+cborld</strong>
            <br/><br/>
            ${cborldHex}
            <br/><br/>
            JSON-LD size: ${jsonldSize} bytes<br/>
            CBOR-LD size: ${cborldSize} bytes<br/>
            Compression : ${percentage}%<br/>
            <hr>
            <strong>${mediaType}</strong>
            <pre style="font-size: 75%"
              >${jsonldDiagnostic.match(/.{1,100}/g).join('\n')}
            </pre>
            <hr>
            <strong>CBOR-LD Diagnostic Mode</strong>
            <pre style="font-size: 75%"
              >${cborDiagnostic.match(/.{1,100}/g).join('\n')}}
            </pre>`;
        } catch(e) {
          console.error(
            'respec-vc error: Failed to generate CBOR-LD output.',
            e, example.innerText);
        }
      });
    }

    /**
     * Add a VC QR Code example tab.
     *
     * @global string verificationMethod
     * @param {object} suite - Suite object.
     * @param {string} tabText - Text to display on the tab.
     * @param {string | undefined} key - Optional key to use for the proof.
     */
    async function addVcQrTab(suite, tabText, key) {
      let verifiableCredentialProof;

      if(key) {
        suite.verificationMethod = 'did:key:' + key.publicKeyMultibase;
      } else {
        suite.verificationMethod = verificationMethod;
      }

      await addTab('QR Code', `Encoded as a QR Code`, tabText, async () => {
        // attach the proof
        try {
          verifiableCredentialProof = await attachProof({credential, suite});
          const cborldBytes = await cborld.encode({
            jsonldDocument: verifiableCredentialProof,
            documentLoader
          });
          const jsonldDiagnostic =
            JSON.stringify(verifiableCredentialProof, null, 2);
          const header = (verifiableCredentialProof.type
            .includes('VerifiablePresentation')) ? 'VP1-' : 'VC1-';

          const {
            version, payload, imageDataUrl
          } = await vpqr.util.toQrCode({
            header,
            cborldBytes,
            documentLoader,
            moduleSize: 2,
            margin: 16
          });

          const qrImage = imageDataUrl;
          const qrText = payload;
          return `
            <strong>image/png</strong>
            <br/><br/>
            <img src="${qrImage}" /><br/>
            QR Code version: ${version}<br/>
            Error correction: Low<br/>
            <hr>
            <strong>QR Code Content (text)</strong>
            <pre style="font-size: 75%"
              >${qrText.match(/.{1,100}/g).join('\n')}
            </pre>
            <hr>
            <strong>JSON-LD Diagnostic Mode</strong>
            <pre style="font-size: 75%"
              >${jsonldDiagnostic.match(/.{1,100}/g).join('\n')}}
            </pre>`;
        } catch(e) {
          console.error(
            'respec-vc error: Failed to generate QR Code output.',
            e, example.innerText);
        }
      });
    }

    function hasTab(identifier) {
      return tabTypes.indexOf(identifier) > -1;
    }

    // set up the unsigned button
    if(credential.type.includes('VerifiablePresentation')) {
      await addTab(
        'unsigned',
        'Unsecured presentation',
        'Presentation',
        () => example.outerHTML,
      );
    } else {
      await addTab(
        'unsigned',
        'Unsecured credential',
        'Credential',
        () => example.outerHTML,
      );
    }

    for(const {proof, key, label} of exampleProofs) {
      if(hasTab(proof.cryptosuite)) {
        await addProofTab(proof, label, key);
      }
    }

    if(hasTab(suiteEd25519Signature2020.type)) {
      await addProofTab(suiteEd25519Signature2020, 'Ed25519Signature2020');
    }

    if(hasTab('cbor-ld')) {
      let ecdsaProof;
      let ecdsaKey;
      for(const {proof, key, label} of exampleProofs) {
        if(label === 'ecdsa') {
          ecdsaProof = proof;
          ecdsaKey = key;
        }
      }
      await addCborldTab(ecdsaProof, 'Binary', ecdsaKey);
    }

    if(hasTab('qr')) {
      let ecdsaProof;
      let ecdsaKey;
      for(const {proof, key, label} of exampleProofs) {
        if(label === 'ecdsa') {
          ecdsaProof = proof;
          ecdsaKey = key;
        }
      }
      await addVcQrTab(ecdsaProof, 'QR Code', ecdsaKey);
    }

    if(hasTab('jose')) {
      await addTab('jose', 'Secured with JOSE', 'jose',
        async () => {
          const joseExample = await getJoseExample(privateKeyJwk, credential);
          return getJoseHtml({joseExample});
        });
    }

    if(hasTab('cose')) {
      await addTab('cose', 'Secured with COSE', 'cose',
        async () => {
          const coseExample = await getCoseExample(privateKeyJwk, credential);
          return getCoseHtml({coseExample});
        });
    }

    if(hasTab('sd-jwt')) {
      await addTab('sd-jwt', 'Secured with SD-JWT', 'sd-jwt', async () => {
        const sdJwtExample =
          await getSdJwtExample(vcProofExampleIndex, privateKeyJwk, credential);
        return getSdJwtHtml({sdJwtExample});
      });
    }
    // append the tabbed content

    // replace the original example with the tabbed content
    const container = example.parentNode;
    // set first radio as checked
    tabbedContent.querySelector('input').toggleAttribute('checked');
    container.append(tabbedContent);
    example.remove();
  }
}

// setup exports on window
window.respecVc = {
  addContext,
  createVcExamples,
};
