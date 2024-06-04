export default function(source) {
  return source.replace(/require\('node:url'\)/g, 'require(\'url\')');
}
