import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as ecdsaSd2023Cryptosuite
  from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import * as examples1Context from '@digitalbazaar/credentials-examples-context';
import * as odrlContext from '@digitalbazaar/odrl-context';
import {defaultDocumentLoader, issue} from '@digitalbazaar/vc';
import {extendContextLoader, purposes} from 'jsonld-signatures';
import {getCoseHtml, getJoseHtml, getSdJwtHtml} from './src/html';
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
import {getJoseExample} from './src/jose';
import {getSdJwtExample} from './src/sd-jwt';
import {privateKey} from './src/common';

// default types
const TAB_TYPES = ['ecdsa-sd-2023', 'eddsa-rdfc-2022', 'jose', 'sd-jwt', 'cose'];
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

  .vc-jose-cose-tabbed, .vc-jose-cose-tabbed-jwt, .vc-jose-cose-tabbed-sd-jwt, .vc-jose-cose-tabbed-cose,
  .sd-jwt-tabbed {
    overflow-x: hidden;
    margin: 0 0;
  }

  .vc-jose-cose-tabbed h1, .vc-jose-cose-jwt-tabbed h1, .vc-jose-cose-sd-jwt-tabbed h1, .vc-jose-cose-cose-tabbed h1,
  .sd-jwt-tabbed h1 {
    font-size: 1em;
    margin: 0 0;
  }

  .vc-jose-cose-tabbed [type="radio"], .vc-jose-cose-tabbed-jwt [type="radio"], .vc-jose-cose-tabbed-sd-jwt [type="radio"], .vc-jose-cose-tabbed-cose [type="radio"],
  .sd-jwt-tabbed [type="radio"] {
    display: none;
  }

  .vc-jose-cose-tabs, .vc-jose-cose-jwt-tabs, .vc-jose-cose-sd-jwt-tabs, .vc-jose-cose-cose-tabs,
  .sd-jwt-tabs {
    display: flex;
    align-items: stretch;
    list-style: none;
    padding: 0;
    border-bottom: 1px solid #ccc;
  }

  li.vc-jose-cose-tab, li.vc-jose-cose-jwt-tab, li.vc-jose-cose-sd-jwt-tab, li.vc-jose-cose-cose-tab,
  li.sd-jwt-tab {
    margin: 0 0;
    margin-left: 8px;
  }

  .vc-jose-cose-tab>label, .vc-jose-cose-jwt-tab>label, .vc-jose-cose-sd-jwt-tab>label, .vc-jose-cose-cose-tab>label,
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

  .vc-jose-cose-tab:hover label, .vc-jose-cose-jwt-tab:hover label, .vc-jose-cose-sd-jwt-tab:hover label, .vc-jose-cose-cose-tab:hover label,
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

  .vc-jose-cose-tabbed [type="radio"]:nth-of-type(1):checked~.vc-jose-cose-tabs .vc-jose-cose-tab:nth-of-type(1) label,
  .vc-jose-cose-tabbed [type="radio"]:nth-of-type(2):checked~.vc-jose-cose-tabs .vc-jose-cose-tab:nth-of-type(2) label,
  .vc-jose-cose-tabbed [type="radio"]:nth-of-type(3):checked~.vc-jose-cose-tabs .vc-jose-cose-tab:nth-of-type(3) label,
  .sd-jwt-tabbed [type="radio"]:nth-of-type(1):checked~.sd-jwt-tabs .sd-jwt-tab:nth-of-type(1) label,
  .sd-jwt-tabbed [type="radio"]:nth-of-type(2):checked~.sd-jwt-tabs .sd-jwt-tab:nth-of-type(2) label,
  .sd-jwt-tabbed [type="radio"]:nth-of-type(3):checked~.sd-jwt-tabs .sd-jwt-tab:nth-of-type(3) label {
    border-bottom-color: #fff;
    background: #fff;
    color: #222;
  }

  .vc-jose-cose-tabbed [type="radio"]:nth-of-type(1):checked~.vc-jose-cose-tab-content:nth-of-type(1),
  .vc-jose-cose-tabbed [type="radio"]:nth-of-type(2):checked~.vc-jose-cose-tab-content:nth-of-type(2),
  .vc-jose-cose-tabbed [type="radio"]:nth-of-type(3):checked~.vc-jose-cose-tab-content:nth-of-type(3),
  .sd-jwt-tabbed [type="radio"]:nth-of-type(1):checked~.sd-jwt-tab-content:nth-of-type(1),
  .sd-jwt-tabbed [type="radio"]:nth-of-type(2):checked~.sd-jwt-tab-content:nth-of-type(2),
  .sd-jwt-tabbed [type="radio"]:nth-of-type(3):checked~.sd-jwt-tab-content:nth-of-type(3) {
    display: block;
  }

  .sd-jwt-header, .jwt-header, .vc-jose-cose-jwt .header, .vc-jose-cose-sd-jwt .header, .vc-jose-cose-cose .header {
    color: red;
  }
  .sd-jwt-payload, .jwt-payload, .vc-jose-cose-jwt .payload, .vc-jose-cose-sd-jwt .payload, .vc-jose-cose-cose .payload {
    color: green;
  }

  .sd-jwt-signature, .jwt-signature, .vc-jose-cose-jwt .signature, .vc-jose-cose-sd-jwt .signature, .vc-jose-cose-cose .signature {
    color: blue;
  }

  .sd-jwt-disclosure, .vc-jose-cose-jwt .disclosure, .vc-jose-cose-sd-jwt .disclosure, .vc-jose-cose-cose .disclosure {
    color: purple;
  }

  .sd-jwt-compact, .jwt-compact, .vc-jose-cose-jwt .compact, .vc-jose-cose-sd-jwt .compact, .vc-jose-cose-cose .compact {
    background-color: rgba(0,0,0,.03);
  }

  .cose-text, .jose-text, .vc-jose-cose-jwt .text, .vc-jose-cose-sd-jwt .text, .vc-jose-cose-cose .text {
    font-family: monospace;
    color: green;
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

    if(tabTypes.indexOf('jose') > -1) {
      addTab('jose', 'Secured with JOSE', async () => {
        const joseExample = await getJoseExample(privateKey, credential);
        return getJoseHtml({jwtExample: joseExample});
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
