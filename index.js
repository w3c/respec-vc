import vc from '@digitalbazaar/vc';
import contexts from '@digitalbazaar/vc/lib/contexts';
import {extendContextLoader} from 'jsonld-signatures';
import ed25519Context from 'ed25519-signature-2020-context';
import * as jose from 'jose';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';

// append 2020 signature suite to cached contexts
contexts[ed25519Context.CONTEXT_URL] = ed25519Context.CONTEXT;
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
  throw new Error(`Document loader unable to load URL "${url}".`);
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
    JSON.stringify(payload, null, 2);
  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader(header)
    .sign(jwk.privateKey);

  return description + '\n\n--------------- JWT ---------------\n\n' + jwt;
};

async function attachProof({credential, suite}) {
  const credentialCopy = JSON.parse(JSON.stringify(credential));
  return vc.issue({credential: credentialCopy, suite, documentLoader});
};

function addVcExampleStyles() {
  const exampleStyles = document.createElement('style');

  exampleStyles.innerText += `.example .tab {
    background-color: rgba(0, 0, 0, 0.05);
    border: solid gray thin;
    border-radius: 4px 4px 0px 0px;
    border-color: #574b0f;
    padding: 4px;
    cursor: default;
    margin: 4px;
  }`;
  exampleStyles.innerText += `.example .tab.selected {
    background-color: inherit;
    border-bottom: solid #fcfaee thin;
  }`;
  exampleStyles.innerText += `.example .tab:hover {
    color: #034575;
    background-color: #e0cb52;
  }`;
  exampleStyles.innerText += `.example .tab-separator {
    background: gray;
    height: 1px;
    border: 1px;
  }`;

  document.getElementsByTagName('head')[0].appendChild(exampleStyles);
}

function addVcExampleScripts() {
  const exampleScripts = document.createElement('script');
  exampleScripts.type = 'text/javascript';
  exampleScripts.text += `
  /**
   * Displays a Verifiable Credential example given an element that contains
   * PRE tags and an elementClass to match against and display.
   */
  function displayVcExample(element, elementClass) {
    // find all SPAN.tab sibling elements in an example block
    const tabs = element.parentElement.querySelectorAll('.tab');
    // highlight the currently clicked on tab
    for(tab of tabs) {
      tab.classList.remove('selected');
    }
    element.classList.add('selected');

    // find all PRE sibling elements in an example block
    const examples = element.parentElement.querySelectorAll('pre');
    // display the provided elementClass, hide all other PRE blocks
    for(example of examples) {
      if(example.classList.contains(elementClass)) {
        example.style.display = 'block';
      } else {
        example.style.display = 'none';
      }
    }
  }

  window.displayVcExample = displayVcExample;
  `;
  document.getElementsByTagName('head')[0].appendChild(exampleScripts);
}
async function createVcExamples() {
  // generate base keypair and signature suite
  const keyPair = await Ed25519VerificationKey2020.generate();
  const suite = new Ed25519Signature2020({
    key: keyPair
  });
  const jwk = await jose.generateKeyPair('ES256');

  // add scripts for examples
  addVcExampleScripts();

  // add styles for examples
  addVcExampleStyles();

  // process every example that needs a vc-proof
  const vcProofExamples = document.querySelectorAll(".vc");
  for(const example of vcProofExamples) {
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

    // set up tab style
    const tabStyle = "";

    const tabRow = document.createElement('div');
    tabRow.setAttribute('style', 'padding: 5px;');

    // set up the unsigned button action
    const unsignedTab = document.createElement('span');
    unsignedTab.setAttribute('style', tabStyle);
    unsignedTab.setAttribute('class', 'tab selected');
    unsignedTab.innerText = 'Credential';
    unsignedTab.setAttribute(
      'onclick', 'window.displayVcExample(this, \'credential\');');
    example.classList.remove('vc');
    example.classList.add('credential');

    // set up the signed proof button action
    const signedProofTab = document.createElement('span');
    signedProofTab.innerText = 'Verifiable Credential (with proof)';
    signedProofTab.setAttribute('style', tabStyle);
    signedProofTab.setAttribute('class', 'tab');
    signedProofTab.setAttribute(
      'onclick', 'window.displayVcExample(this, \'vc-proof\');');
    const preProof = document.createElement('pre');
    preProof.classList.add('vc-proof');
    preProof.style.display = 'none';
    preProof.innerText = JSON.stringify(verifiableCredentialProof, null, 2)
      .match(/.{1,75}/g).join('\n');

    // set up the signed JWT button action
    const signedJwtTab = document.createElement('span');
    signedJwtTab.innerText = 'Verifiable Credential (as JWT)';
    signedJwtTab.setAttribute('class', 'tab');
    signedJwtTab.setAttribute('style', tabStyle);
    signedJwtTab.setAttribute(
      'onclick', 'window.displayVcExample(this, \'vc-jwt\');');
    const preJwt = document.createElement('pre');
    preJwt.classList.add('vc-jwt');
    preJwt.style.display = 'none';
    preJwt.innerText = verifiableCredentialJwt.match(/.{1,75}/g).join('\n');

    // set up the tab separator
    const tabSeparator = document.createElement('div');
    tabSeparator.setAttribute('class', 'tab-separator');

    // prepend the buttons before the preformatted example
    example.before(tabRow);
    example.before(unsignedTab);
    example.before(signedProofTab);
    example.before(signedJwtTab);
    example.before(tabSeparator);

    // append the examples
    example.after(preJwt);
    example.after(preProof);
  }
}

// setup exports on window
window.respecVc = {
  createVcExamples
}
