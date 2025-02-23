const path = require('path');
const webpack = require('webpack');

module.exports = [{
  mode: 'production',
  entry: './index.js',
  plugins: [
    new webpack.ProvidePlugin({
      process: 'process/browser.js',
      Buffer: ['buffer', 'Buffer'],
    }),
  ],
  watch: true,
  resolve: {
    fallback: {
      buffer: require.resolve("buffer/"),
      crypto: require.resolve("crypto-browserify"),
      stream: require.resolve("stream-browserify"),
      vm: require.resolve("vm-browserify"),
      url: require.resolve("url/"),
    },
  },
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
