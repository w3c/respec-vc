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
      example.dataset?.vcVm || 'did:key:' + keyPair.publicKey;

    const tabTypes = example.dataset?.vcTabs
      || ['Ed25519Signature2020', 'vc-jwt'];

    // extract and parse the example as JSON
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

    // set up the tab labels
    const tabLabels = document.createElement("ul");
    tabLabels.setAttribute('class', 'vc-tabs');
    tabbedContent.appendChild(tabLabels);

    function addTab(suffix, labelText, contentHTML) {
      const button = document.createElement('input');
      button.setAttribute('type', 'radio');
      button.setAttribute('id', `vc-tab${vcProofExampleIndex}${suffix}`);
      button.setAttribute('name', `vc-tabs${vcProofExampleIndex}`);
      if (tabbedContent.firstChild.tagName === 'INPUT') {
        // place this one last of the inputs
        [...tabbedContent.querySelectorAll('input')].pop().after(button);
      } else {
        tabbedContent.prepend(button);
      }

      const label = document.createElement("li");
      label.setAttribute('class', 'vc-tab');
      label.innerHTML = `<label for='${button.getAttribute('id')}'>${labelText}</label>`;
      tabLabels.appendChild(label);

      const content = document.createElement('div');
      content.setAttribute('class', 'vc-tab-content');
      content.innerHTML = contentHTML;
      tabbedContent.appendChild(content);
    }
    // set up the unsigned button
    addTab('unsigned', 'Verifiable Credential', example.outerHTML);
    // set up the signed proof button
    addTab('Ed25519Signature2020', 'Secured with Data Integrity',
      `<pre>${JSON.stringify(verifiableCredentialProof, null, 2).match(/.{1,75}/g).join('\n')}</pre>`);
    // set up the signed JWT button
    addTab('vc-jwt', 'Secured with VC-JWT',
      `<pre>${verifiableCredentialJwt.match(/.{1,75}/g).join('\n')}</pre>`);

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
}
