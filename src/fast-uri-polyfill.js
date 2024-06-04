// eslint-disable-next-line unicorn/prefer-module
module.exports = function(source) {
  return source.replace(/require\('node:url'\)/g, 'require(\'url\')');
};
