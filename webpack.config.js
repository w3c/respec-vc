const webpack = require('webpack');
const path = require('path');
const NodePolyfillPlugin = require('node-polyfill-webpack-plugin');

module.exports = [{
  mode: 'development',
  plugins: [
    new webpack.ProvidePlugin({
      entry: './index.js',
      process: 'process/browser.js',
      Buffer: ['buffer', 'Buffer'],
    }),
    new NodePolyfillPlugin()
  ],
  watch: true,
  module: {
    rules: [
      {
        test: /node_modules\/fast-uri/,
        use: [
          {
            loader: path.resolve('src/fast-uri-polyfill.js')
          }
        ]
      }
    ]
  }
}];
