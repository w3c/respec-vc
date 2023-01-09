import {defaultDocumentLoader, issue} from '@digitalbazaar/vc';
import {extendContextLoader} from 'jsonld-signatures';
import ed25519Context from 'ed25519-signature-2020-context';
import * as examples1Context from '@digitalbazaar/credentials-examples-context';
import * as jose from 'jose';
import * as odrlContext from '@digitalbazaar/odrl-context';
import examples2Context from './contexts/credentials/examples/v2';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';

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

  return Date.parse(xmlDateTime)/1000;
}

// transform the input credential to a JWT
async function transformToJwt({credential, kid, jwk}) {
  const header = {alg: 'ES256', typ: 'JWT'};
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
};

async function attachProof({credential, suite}) {
  const credentialCopy = JSON.parse(JSON.stringify(credential));
  return issue({credential: credentialCopy, suite, documentLoader});
};

function addVcExampleStyles() {
  const exampleStyles = document.createElement('style');

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

  .vc-tabbed [type="radio"]:nth-of-type(1):checked ~ .vc-tabs .vc-tab:nth-of-type(1) label,
  .vc-tabbed [type="radio"]:nth-of-type(2):checked ~ .vc-tabs .vc-tab:nth-of-type(2) label,
  .vc-tabbed [type="radio"]:nth-of-type(3):checked ~ .vc-tabs .vc-tab:nth-of-type(3) label {
    border-bottom-color: #fff;
    background: #fff;
    color: #222;
  }
  
  .vc-tabbed [type="radio"]:nth-of-type(1):checked ~ .vc-tab-content:nth-of-type(1),
  .vc-tabbed [type="radio"]:nth-of-type(2):checked ~ .vc-tab-content:nth-of-type(2),
  .vc-tabbed [type="radio"]:nth-of-type(3):checked ~ .vc-tab-content:nth-of-type(3) {
    display: block;
  }`;

  document.getElementsByTagName('head')[0].appendChild(exampleStyles);
}

function addContext(url, context) {
  contexts[url] = context;
}

async function createVcExamples() {
  // generate base keypair and signature suite
  const keyPair = await Ed25519VerificationKey2020.generate();
  const suite = new Ed25519Signature2020({
    key: keyPair
  });
  const jwk = await jose.generateKeyPair('ES256');

  // add styles for examples
  addVcExampleStyles();

  // process every example that needs a vc-proof
  const vcProofExamples = document.querySelectorAll(".vc");
  let vcProofExampleIndex = 0;
  for(const example of vcProofExamples) {
    vcProofExampleIndex++;
    const verificationMethod = example.getAttribute('data-vc-vm');
    suite.verificationMethod =
      verificationMethod || 'did:key:' + keyPair.publicKey;

    // extract and sign the example
    const originalText = example.innerHTML;
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

    // attach the proof
    let verifiableCredentialProof;
    try {
      verifiableCredentialProof = await attachProof({credential, suite});
    } catch(e) {
      console.error(
        'respec-vc error: Failed to attach proof to Verifiable Credential.',
        e, example.innerText);
      continue;
    }

    // convert to a JWT
    let verifiableCredentialJwt;
    try {
      verifiableCredentialJwt = await transformToJwt({
        credential, kid: suite.verificationMethod, jwk});
    } catch(e) {
      console.error(
        'respec-vc error: Failed to convert Credential to JWT.',
        e, example.innerText);
      continue;
    }

    // set up the tabbed content
    const tabbedContent = document.createElement('div');
    tabbedContent.setAttribute('class', 'vc-tabbed');

    // set up the unsigned button
    const unsignedTabBtn = document.createElement('input');
    unsignedTabBtn.setAttribute('type', 'radio');
    unsignedTabBtn.setAttribute('id', `vc-tab${vcProofExampleIndex}1`);
    unsignedTabBtn.setAttribute('name', `vc-tabs${vcProofExampleIndex}`);
    unsignedTabBtn.setAttribute('checked', 'checked');
    tabbedContent.appendChild(unsignedTabBtn);

    // set up the signed proof button
    const signedProofTabBtn = document.createElement('input');
    signedProofTabBtn.setAttribute('type', 'radio');
    signedProofTabBtn.setAttribute('id', `vc-tab${vcProofExampleIndex}2`);
    signedProofTabBtn.setAttribute('name', `vc-tabs${vcProofExampleIndex}`);
    tabbedContent.appendChild(signedProofTabBtn);

    // set up the signed JWT button
    const signedJwtTabBtn = document.createElement('input');
    signedJwtTabBtn.setAttribute('type', 'radio');
    signedJwtTabBtn.setAttribute('id', `vc-tab${vcProofExampleIndex}3`);
    signedJwtTabBtn.setAttribute('name', `vc-tabs${vcProofExampleIndex}`);
    tabbedContent.appendChild(signedJwtTabBtn);

    // set up the tab labels
    const tabLabels = document.createElement("ul");
    tabLabels.setAttribute('class', 'vc-tabs');
    tabbedContent.appendChild(tabLabels);

    const unsignedLabel = document.createElement("li");
    unsignedLabel.setAttribute('class', 'vc-tab');
    unsignedLabel.innerHTML = `<label for='${unsignedTabBtn.getAttribute('id')}'>Credential</label>`;
    tabLabels.appendChild(unsignedLabel)

    const signedProofLabel = document.createElement("li");
    signedProofLabel.setAttribute('class', 'vc-tab');
    signedProofLabel.innerHTML = `<label for='${signedProofTabBtn.getAttribute('id')}'>Verifiable Credential (with proof)</label>`;
    tabLabels.appendChild(signedProofLabel)

    const signedJwtLabel = document.createElement("li");
    signedJwtLabel.setAttribute('class', 'vc-tab');
    signedJwtLabel.innerHTML = `<label for='${signedJwtTabBtn.getAttribute('id')}'>Verifiable Credential (as JWT)</label>`;
    tabLabels.appendChild(signedJwtLabel)

    // append the tabbed content

    const container = example.parentNode;
    const unsignedContent = document.createElement('div');
    unsignedContent.setAttribute('class', 'vc-tab-content');
    // Move the credential example to the unsigned tab
    unsignedContent.append(example);
    tabbedContent.appendChild(unsignedContent);

    const signedProofContent = document.createElement('div');
    signedProofContent.setAttribute('class', 'vc-tab-content');
    signedProofContent.innerHTML = `<pre>${JSON.stringify(verifiableCredentialProof, null, 2).match(/.{1,75}/g).join('\n')}</pre>`;
    tabbedContent.appendChild(signedProofContent);

    const signedJwtContent = document.createElement('div');
    signedJwtContent.setAttribute('class', 'vc-tab-content');
    signedJwtContent.innerHTML = `<pre>${verifiableCredentialJwt.match(/.{1,75}/g).join('\n')}</pre>`;
    tabbedContent.appendChild(signedJwtContent);

    // replace the original example with the tabbed content

    container.append(tabbedContent);
  }
}

// setup exports on window
window.respecVc = {
  addContext,
  createVcExamples
}
