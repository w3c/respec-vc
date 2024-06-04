import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as ecdsaSd2023Cryptosuite
  from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import * as examples1Context from '@digitalbazaar/credentials-examples-context';
import * as odrlContext from '@digitalbazaar/odrl-context';
import {defaultDocumentLoader, issue} from '@digitalbazaar/vc';
import {extendContextLoader, purposes} from 'jsonld-signatures';
import {getCoseHtml, getJwtHtml, getSdJwtHtml} from './src/html';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import ed25519Context from 'ed25519-signature-2020-context';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {
  Ed25519VerificationKey2020,
} from '@digitalbazaar/ed25519-verification-key-2020';
import {
  cryptosuite as eddsaRdfc2022CryptoSuite,
} from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import examples2Context from './contexts/credentials/examples/v2';
import {getCoseExample} from './src/cose';
import {getJwtExample} from './src/jwt';
import {getSdJwtExample} from './src/sd-jwt';
import {privateKey} from './src/common';

// default types
const TAB_TYPES = ['ecdsa-sd-2023', 'eddsa-rdfc-2022', 'jwt', 'sd-jwt', 'cose'];
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
  return defaultDocumentLoader(url);
});

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
    cryptosuite: createSignCryptosuite({
      mandatoryPointers: ['/issuer'],
    }),
  });
  // Ed25519Signature2020
  const keyPairEd25519VerificationKey2020 = await Ed25519VerificationKey2020
    .generate();
  const keyPairEd25519Multikey = await Ed25519Multikey
    .from(keyPairEd25519VerificationKey2020);
  const suiteEd25519Signature2020 = new Ed25519Signature2020({
    key: keyPairEd25519VerificationKey2020,
  });
  // eddsa-rdfc-2022
  const suiteEd25519Multikey = new DataIntegrityProof({
    signer: keyPairEd25519Multikey.signer(),
    cryptosuite: eddsaRdfc2022CryptoSuite,
  });
  // vc-jwt and vc-jose-cose

  // add styles for examples
  addVcExampleStyles();

  // process every example that needs a vc-proof
  const vcProofExamples = document.querySelectorAll('.vc');
  let vcProofExampleIndex = 0;
  for(const example of vcProofExamples) {
    vcProofExampleIndex++;

    const verificationMethod = example.dataset?.vcVm ||
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
     * Add tab to tab container in DOM. Run callback function to populate
     * content on tab click.
     *
     * @param {string} suffix - One of the TAB_TYPES values (or `unsigned`).
     * @param {string} labelText - Human readable label name.
     * @param {contentCallback} callback - Function which returns HTML.
     */
    function addTab(suffix, labelText, callback) {
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
      content.style.minHeight = `${example.clientHeight}px`;
      tabbedContent.appendChild(content);

      if(suffix === 'unsigned') {
        content.innerHTML = callback();
      } else {
        label.addEventListener('click', async () => {
          content.innerHTML = await callback();
        }, {once: true});
      }
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

      addTab(label, `Secured with Data Integrity (${label})`, async () => {
        // attach the proof
        try {
          verifiableCredentialProof = await attachProof({credential, suite});
          return `<pre>${JSON.stringify(verifiableCredentialProof, null, 2)
            .match(/.{1,75}/g).join('\n')}</pre>`;
        } catch(e) {
          console.error(
            'respec-vc error: Failed to attach proof to Verifiable Credential.',
            e, example.innerText);
        }
      });
    }

    // set up the unsigned button
    addTab('unsigned', 'Verifiable Credential', () => example.outerHTML);

    if(tabTypes.indexOf(suiteEd25519Signature2020.type) > -1) {
      await addProofTab(suiteEd25519Signature2020);
    }
    if(tabTypes.indexOf(suiteEd25519Multikey.cryptosuite) > -1) {
      await addProofTab(suiteEd25519Multikey);
    }
    if(tabTypes.indexOf(suiteEcdsaMultiKey.cryptosuite) > -1) {
      await addProofTab(suiteEcdsaMultiKey);
    }

    if(tabTypes.indexOf('jwt') > -1) {
      addTab('jwt', 'Secured with JWT', async () => {
        const jwtExample = await getJwtExample(privateKey, credential);
        return getJwtHtml({jwtExample});
      });
    }

    if(tabTypes.indexOf('sd-jwt') > -1) {
      addTab('sd-jwt', 'Secured with SD-JWT', async () => {
        // eslint-disable-next-line max-len
        const sdJwtExample = await getSdJwtExample(vcProofExampleIndex, privateKey, credential);
        return getSdJwtHtml({sdJwtExample});
      });
    }

    if(tabTypes.indexOf('cose') > -1) {
      addTab('cose', 'Secured with COSE', async () => {
        const coseExample = await getCoseExample(privateKey, credential);
        return getCoseHtml({coseExample});
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
