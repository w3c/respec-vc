export const getJoseHtml = ({joseExample}) => {
  return `
<div class="vc-jose-cose-jwt-tabbed">
    <div class="vc-jose-cose-jwt-tab-content">
${joseExample}
    </div>
</div>`;
};

export const getSdJwtHtml = ({sdJwtExample}) => {
  return `
<div>
${sdJwtExample}
</div>
`.trim();
};

export const getCoseHtml = ({coseExample}) => {
  return `
<div class="vc-jose-cose-cose-tabbed">
    <div class="vc-jose-cose-cose-tab-content">
${coseExample}
    </div>
</div>`;
};
