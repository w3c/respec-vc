const path = require('path');
const NodePolyfillPlugin = require('node-polyfill-webpack-plugin');

module.exports = [{
  mode: 'development',
  plugins: [
    new NodePolyfillPlugin()
  ],
  watch: true,
  module: {
    rules: [
      {
        test: /node_modules\/fast-uri/,
        use: [
          {
            loader: path.resolve('src/index.js')
          }
        ]
      }
    ]
  }
}];
