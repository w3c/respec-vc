module.exports = function(source) {
  return source.replace(/require\('node:url'\)/g, 'require(\'url\')');
};
