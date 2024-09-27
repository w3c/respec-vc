import * as jose from 'jose';
import {base64url, issuer, key, text} from '@transmute/verifiable-credentials';
import crypto from 'crypto';
import yaml from 'yaml';

const calculateHash = value => {
  return base64url.encode(crypto.createHash('sha256').update(value).digest());
};

const customJSONStringify = obj => {
  return JSON.stringify(obj, null, 2)
    .replace(/\n/g, '<br>').replace(/\s/g, '&nbsp;');
};

const generateDisclosureHtml = (claimName, hash, disclosure, contents) => {
  return `
<div class="disclosure">
    <h3 id="sd-jwt-claim-${hash}">Claim: <span class="claim-name">${claimName}</span></h3>
    <p><strong>SHA-256 Hash:</strong> <span class="hash">${hash}</span></p>
    <p><strong>Disclosure(s):</strong> <span class="disclosure-value">${disclosure}</span></p>
    <p><strong>Contents:</strong> <span class="contents">${customJSONStringify(contents)}</span></p>
</div>
`;
};

const getSdHtml = vc => {
  const [token, ...disclosure] = vc.split('~');
  const [header, payload, signature] = token.split('.');
  const disclosures = disclosure.map(d => {
    return `~<span class="sd-jwt-disclosure">${d}</span>`;
  }).join('');
  return `
<div class="sd-jwt-compact">
<span class="sd-jwt-header">${header}</span>
.<span class="sd-jwt-payload">${payload}</span>
.<span class="sd-jwt-signature">${signature}</span>
${disclosures}
</div>`;
};

const getHeadersHtml = vc => {
  const [token] = vc.split('~');
  const [header] = token.split('.');
  const decoded = new TextDecoder().decode(base64url.decode(header));
  const headerJson = JSON.parse(decoded);
  return `<pre class="header-value">${customJSONStringify(headerJson)}</pre>`;
};

const getPayloadHtml = vc => {
  const [token] = vc.split('~');
  const [, payload] = token.split('.');
  const decoded = new TextDecoder().decode(base64url.decode(payload));
  const payloadJson = JSON.parse(decoded);
  return `<pre class="header-value">${customJSONStringify(payloadJson)}</pre>`;
};

const getDisclosuresHtml = async vc => {
  const [, ...disclosures] = vc.split('~');
  const disclosureHtml = disclosures.map(disclosure => {
    const decoded = new TextDecoder().decode(base64url.decode(disclosure));
    const decodedDisclosure = JSON.parse(decoded);
    const [, ...claimPath] = decodedDisclosure;
    claimPath.pop();
    const hash = calculateHash(disclosure);
    return generateDisclosureHtml(claimPath, hash, disclosure,
      decodedDisclosure);
  });

  return `<div class="disclosures">${disclosureHtml.join('\n')}</div>`;
};

export const generateIssuerClaims = example => {
  return yaml.stringify(example).replace(/id: /g, '!sd id: ')
    .replace(/type:/g, '!sd type:');
};

const getCredential = async (
  privateKey,
  byteSigner,
  messageJson,
) => {
  return issuer({
    alg: privateKey.alg,
    type: 'application/vc+ld+json+sd-jwt',
    signer: byteSigner,
  }).issue({
    claimset: new TextEncoder().encode(generateIssuerClaims(messageJson)),
  });
};

const getPresentation = async (
  privateKey,
  byteSigner,
  message,
) => {
  if(Array.isArray(message.verifiableCredential) &&
    message.verifiableCredential.length === 0) {
    delete message.verifiableCredential;
  }
  return getCredential(privateKey, byteSigner, message);
};

export const getBinaryMessage = async (
  privateKey,
  messageType,
  messageJson,
) => {
  const byteSigner = {
    sign: async bytes => {
      const jws = await new jose.CompactSign(bytes)
        .setProtectedHeader({kid: privateKey.kid, alg: privateKey.alg})
        .sign(await key.importKeyLike({
          type: 'application/jwk+json',
          content: new TextEncoder().encode(JSON.stringify(privateKey)),
        }));
      return text.encoder.encode(jws);
    },
  };
  switch(messageType) {
    case 'application/vc+sd-jwt': {
      return getCredential(privateKey, byteSigner, messageJson);
    }
    case 'application/vp+sd-jwt':
    case 'EnvelopedVerifiablePresentation': {
      return getPresentation(privateKey, byteSigner, messageJson);
    }
    default: {
      throw new Error('Unknown message type');
    }
  }
};

export const getSdJwtExample = async (
  index,
  privateKey,
  messageJson,
  prefix = 'sd-jwt',
) => {
  const type = Array.isArray(messageJson.type) ?
    messageJson.type : [messageJson.type];
  let messageType;
  if(type.includes('VerifiableCredential')) {
    messageType = 'application/vc+sd-jwt';
  } else if(type.includes('VerifiablePresentation') ||
    type.includes('EnvelopedVerifiablePresentation')) {
    messageType = 'application/vp+sd-jwt';
  } else {
    throw new Error('Unknown message type');
  }

  const binaryMessage =
    await getBinaryMessage(privateKey, messageType, messageJson);
  const message = new TextDecoder().decode(binaryMessage);

  if(Array.isArray(messageJson.verifiableCredential) &&
    messageJson.verifiableCredential.length === 0) {
    delete messageJson.verifiableCredential;
  }

  const encoded = getSdHtml(message);
  const header = getHeadersHtml(message);
  const payload = getPayloadHtml(message);
  const disclosures = await getDisclosuresHtml(message);

  const uniqueId = `${prefix}-${index}-${Math.random().toString(36).substring(2, 9)}`;

  return `
<div class="sd-jwt-tabbed">
    <input type="radio" id="${uniqueId}-encoded" name="${uniqueId}-tabs" checked="checked" tabindex="0">
    <input type="radio" id="${uniqueId}-decoded" name="${uniqueId}-tabs" tabindex="0">
    <input type="radio" id="${uniqueId}-disclosures" name="${uniqueId}-tabs" tabindex="0">
    <ul class="sd-jwt-tabs">
      <li class="sd-jwt-tab">
        <label for="${uniqueId}-encoded">Encoded</label>
      </li>
      <li class="sd-jwt-tab">
        <label for="${uniqueId}-decoded">Decoded</label>
      </li>
      <li class="sd-jwt-tab">
        <label for="${uniqueId}-disclosures">Issuer Disclosures</label>
      </li>
    </ul>
    <div class="sd-jwt-tab-content" id="${uniqueId}-content-encoded">
      ${encoded}
    </div>
    <div class="sd-jwt-tab-content" id="${uniqueId}-content-decoded">
      ${header}
      ${payload}
    </div>
    <div class="sd-jwt-tab-content" id="${uniqueId}-content-disclosures">
      ${disclosures}
    </div>
</div>
`;
};
