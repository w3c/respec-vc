import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as ecdsaSd2023Cryptosuite
  from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import * as examples1Context from '@digitalbazaar/credentials-examples-context';
import * as jose from 'jose';
import * as odrlContext from '@digitalbazaar/odrl-context';
import {purposes, extendContextLoader} from 'jsonld-signatures';
import {defaultDocumentLoader, issue} from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import ed25519Context from 'ed25519-signature-2020-context';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {cryptosuite as eddsaRdfc2022CryptoSuite} from
  '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import examples2Context from './contexts/credentials/examples/v2';

// default types
const TAB_TYPES = ['ecdsa-sd-2023', 'eddsa-rdfc-2022', 'vc-jwt'];
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
      document: context
    };
  }
  return defaultDocumentLoader(url);
});

// convert an XML Schema v1.` Datetime value to a UNIX timestamp
function xmlDateTimeToUnixTimestamp(xmlDateTime) {
  if(!xmlDateTime) {
    return undefined;
  }

  return Date.parse(xmlDateTime) / 1000;
}

// transform the input credential to a JWT
async function transformToJwt({credential, kid, jwk}) {
  const header = {alg: 'ES256', typ: 'JWT', kid};
  const payload = {
    vc: credential
  };
  if(credential.expirationDate) {
    payload.exp = xmlDateTimeToUnixTimestamp(credential.expirationDate);
  }
  if(credential.issuer) {
    payload.iss = credential.issuer;
  }
  if(credential.issuanceDate) {
    payload.nbf = xmlDateTimeToUnixTimestamp(credential.issuanceDate);
  }
  if(credential.id) {
    payload.jti = credential.id;
  }
  if(credential.credentialSubject.id) {
    payload.sub = credential.credentialSubject.id;
  }

  // create the JWT description
  let description = '---------------- JWT header ---------------\n' +
    JSON.stringify(header, null, 2);
  description += '\n\n--------------- JWT payload ---------------\n' +
    '// NOTE: The example below uses a valid VC-JWT serialization\n' +
    '//       that duplicates the iss, nbf, jti, and sub fields in the\n' +
    '//       Verifiable Credential (vc) field.\n\n' +
    JSON.stringify(payload, null, 2);
  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader(header)
    .sign(jwk.privateKey);

  return description + '\n\n--------------- JWT ---------------\n\n' + jwt;
}

async function attachProof({credential, suite}) {
  const credentialCopy = JSON.parse(JSON.stringify(credential));
  const options = {credential: credentialCopy, suite, documentLoader};
  options.purposes = new AssertionProofPurpose();
  return issue(options);
}

function addVcExampleStyles() {
  const exampleStyles = document.createElement('style');

  let radioLabels = [...Array(TAB_TYPES.length + 1).keys()]
    .map((i) => {
      const j = i + 1;
      return `.vc-tabbed [type="radio"]:nth-of-type(${j}):checked ~ .vc-tabs .vc-tab:nth-of-type(${j}) label`;
    });
  let radioSelector = [...Array(TAB_TYPES.length + 1).keys()]
    .map((i) => {
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

  ${radioLabels.join(',\n  ')} {
    border-bottom-color: #fff;
    background: #fff;
    color: #222;
  }

  ${radioSelector.join(',\n  ')} {
    display: block;
  }`;

  document.getElementsByTagName('head')[0].appendChild(exampleStyles);
}

function addContext(url, context) {
  contexts[url] = context;
}

async function createVcExamples() {
  // generate base keypair and signature suites
  // ecdsa-sd-2023
  const keyPairEcdsaMultikeyKeyPair = await EcdsaMultikey
    .generate({curve: 'P-256'});
  const {createSignCryptosuite} = ecdsaSd2023Cryptosuite;
  const suiteEcdsaMultiKey = new DataIntegrityProof({
    signer: keyPairEcdsaMultikeyKeyPair.signer(),
    cryptosuite: createSignCryptosuite()
  });
  // Ed25519Signature2020
  const keyPairEd25519VerificationKey2020 = await Ed25519VerificationKey2020
    .generate();
  const keyPairEd25519Multikey = await Ed25519Multikey
    .from(keyPairEd25519VerificationKey2020);
  const suiteEd25519Signature2020 = new Ed25519Signature2020({
    key: keyPairEd25519VerificationKey2020
  });
  // eddsa-rdfc-2022
  const suiteEd25519Multikey = new DataIntegrityProof({
    signer: keyPairEd25519Multikey.signer(),
    cryptosuite: eddsaRdfc2022CryptoSuite
  });
  // vc-jwt
  const jwk = await jose.generateKeyPair('ES256');

  // add styles for examples
  addVcExampleStyles();

  // process every example that needs a vc-proof
  const vcProofExamples = document.querySelectorAll('.vc');
  let vcProofExampleIndex = 0;
  for(const example of vcProofExamples) {
    vcProofExampleIndex++;

    let verificationMethod = example.dataset?.vcVm ||
      'did:key:' + keyPairEd25519VerificationKey2020.publicKeyMultibase;

    const tabTypes = example.dataset?.vcTabs || TAB_TYPES;

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

    // convert to a JWT
    let verifiableCredentialJwt;
    try {
      verifiableCredentialJwt = await transformToJwt({
        credential, kid: verificationMethod, jwk});
    } catch(e) {
      console.error(
        'respec-vc error: Failed to convert Credential to JWT.',
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

    function addTab(suffix, labelText, contentHTML) {
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
      label.innerHTML =
        `<label for='${button.getAttribute('id')}'>${labelText}</label>`;
      tabLabels.appendChild(label);

      const content = document.createElement('div');
      content.setAttribute('class', 'vc-tab-content');
      content.innerHTML = contentHTML;
      tabbedContent.appendChild(content);
    }

    /*
     * Add a Data Integrity based proof example tab
     * @global string verificationMethod
     * @param object suite
     */
    async function addProofTab(suite) {
      let verifiableCredentialProof;
      const label = suite?.cryptosuite || suite.type;

      if(label === 'ecdsa-sd-2023') {
        suite.verificationMethod = 'did:key:' + keyPairEcdsaMultikeyKeyPair
          .publicKeyMultibase;
      } else {
        suite.verificationMethod = verificationMethod;
      }

      // attach the proof
      try {
        verifiableCredentialProof = await attachProof({credential, suite});
        addTab(label, `Secured with Data Integrity (${label})`,
          `<pre>${JSON.stringify(verifiableCredentialProof, null, 2)
            .match(/.{1,75}/g).join('\n')}</pre>`);
      } catch(e) {
        console.error(
          'respec-vc error: Failed to attach proof to Verifiable Credential.',
          e, example.innerText);
      }
    }

    // set up the unsigned button
    addTab('unsigned', 'Verifiable Credential', example.outerHTML);

    if(tabTypes.indexOf(suiteEd25519Signature2020.type) > -1) {
      await addProofTab(suiteEd25519Signature2020);
    }
    if(tabTypes.indexOf(suiteEd25519Multikey.cryptosuite) > -1) {
      await addProofTab(suiteEd25519Multikey);
    }
    if(tabTypes.indexOf(suiteEcdsaMultiKey.cryptosuite) > -1) {
      await addProofTab(suiteEcdsaMultiKey);
    }

    if(tabTypes.indexOf('vc-jwt') > -1) {
      // set up the signed JWT button
      addTab('vc-jwt', 'Secured with VC-JWT',
        `<pre>${verifiableCredentialJwt.match(/.{1,75}/g).join('\n')}</pre>`);
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
  createVcExamples
};
