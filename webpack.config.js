const webpack = require('webpack');
const NodePolyfillPlugin = require('node-polyfill-webpack-plugin');

module.exports = [{
  mode: 'development',
  entry: './index.js',
  plugins: [
    new webpack.ProvidePlugin({
      process: 'process/browser.js',
      Buffer: ['buffer', 'Buffer'],
    }),
    new NodePolyfillPlugin()
  ],
  watch: true,
  resolve: {
    fallback: {
      'buffer': require.resolve('buffer/'),
      'crypto': require.resolve('crypto-browserify'),
      'stream': require.resolve('stream-browserify'),
      'vm': require.resolve('vm-browserify'),
    },
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        use: [
          {
            loader: 'babel-loader',
            options: {
              presets: ['@babel/preset-env'],
              plugins: [
                ['babel-plugin-transform-builtin-extend', {
                  globals: ['Error']
                }],
                ['@babel/plugin-transform-modules-commonjs', {
                  allowTopLevelThis: true
                }]
              ]
            }
          }
        ]
      }
    ]
  }
}];
