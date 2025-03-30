const path = require('path');

module.exports = {
  babel: {
    loaderOptions: (babelLoaderOptions) => ({
      ...babelLoaderOptions,
      plugins: [
        ...(babelLoaderOptions.plugins || []),
        ['@babel/plugin-proposal-optional-chaining', { loose: false }],
        ['@babel/plugin-proposal-nullish-coalescing-operator', { loose: false }],
        ['@babel/plugin-proposal-logical-assignment-operators', { loose: false }],
        ['@babel/plugin-proposal-class-properties', { loose: false }],
        ['@babel/plugin-proposal-private-methods', { loose: false }],
        ['@babel/plugin-proposal-private-property-in-object', { loose: false }]
      ]
    })
  },
  webpack: {
    configure: (webpackConfig) => {
      // Custom webpack configuration for transpiling additional modules.
      webpackConfig.module.rules.push({
        test: /\.(js|mjs)$/,
        include: [
          path.resolve(__dirname, 'node_modules/@mui'),
          path.resolve(__dirname, 'node_modules/chart.js')
        ],
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env'],
            plugins: [
              ['@babel/plugin-proposal-optional-chaining', { loose: false }],
              ['@babel/plugin-proposal-nullish-coalescing-operator', { loose: false }],
              ['@babel/plugin-proposal-logical-assignment-operators', { loose: false }],
              ['@babel/plugin-proposal-class-properties', { loose: false }],
              ['@babel/plugin-proposal-private-methods', { loose: false }],
              ['@babel/plugin-proposal-private-property-in-object', { loose: false }]
            ]
          }
        }
      });

      // No alias or module replacement is needed for ajv when using ajv v8.
      return webpackConfig;
    }
  }
};
