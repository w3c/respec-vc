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

async function attachJwt({credential, iss, jwk}) {
  const jwt = new jose.SignJWT({vc: credential})
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt()
    .setIssuer(iss)
    .sign(jwk.privateKey);

  return jwt;
};

async function attachProof({credential, suite}) {
  const credentialCopy = JSON.parse(JSON.stringify(credential));
  return vc.issue({credential: credentialCopy, suite, documentLoader});
};

async function createVcExamples() {
  // generate base keypair and signature suite
  const keyPair = await Ed25519VerificationKey2020.generate();
  const suite = new Ed25519Signature2020({
    key: keyPair
  });
  const jwk = await jose.generateKeyPair('ES256');

  // process every example that needs a vc-proof
  const vcProofExamples = document.querySelectorAll(".vc");
  for(const example of vcProofExamples) {
    const verificationMethod =
      example.getAttribute('data-vc-verification-method');
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

    const verifiableCredentialProof = await attachProof({credential, suite});
    const verifiableCredentialJwt =
      await attachJwt({credential, iss: suite.verificationMethod, jwk});

    // set up the unsigned button action
    const unsignedButton = document.createElement('button');
    unsignedButton.innerText = 'Credential';
    unsignedButton.setAttribute(
      'onclick', 'window.displayVcExample(this, \'credential\');');
    example.classList.remove('vc');
    example.classList.add('credential');

    // set up the signed proof button action
    const signedProofButton = document.createElement('button');
    signedProofButton.innerText = 'Verifiable Credential (with proof)';
    signedProofButton.setAttribute(
      'onclick', 'window.displayVcExample(this, \'vc-proof\');');
    const preProof = document.createElement('pre');
    preProof.classList.add('vc-proof');
    preProof.style.display = 'none';
    preProof.innerText = JSON.stringify(verifiableCredentialProof, null, 2)
      .match(/.{1,75}/g).join('\n');

    // set up the signed JWT button action
    const signedJwtButton = document.createElement('button');
    signedJwtButton.innerText = 'Verifiable Credential (as JWT)';
    signedJwtButton.setAttribute(
      'onclick', 'window.displayVcExample(this, \'vc-jwt\');');
    const preJwt = document.createElement('pre');
    preJwt.classList.add('vc-jwt');
    preJwt.style.display = 'none';
    preJwt.innerText = verifiableCredentialJwt.match(/.{1,75}/g).join('\n');

    // set up the tab separator
    const tabSeparator = document.createElement('div');
    tabSeparator.style.background = 'gray';
    tabSeparator.style.height = '1px';
    tabSeparator.style.border = '1px';
    tabSeparator.style.margin = '-2px 0px';

    // prepend the buttons before the preformatted example
    example.before(unsignedButton);
    example.before(signedProofButton);
    example.before(signedJwtButton);
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
