// .eslintrc.industry.cjs
module.exports = {
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    ecmaFeatures: {
      jsx: true
    }
  },

  env: {
    browser: true,
    node:    true,
    es2022:  true
  },

  plugins: [
    'security',
    'compat',
    'fp',
    'import',
    'node',
    'promise',
    'prettier',
    'react',
    '@typescript-eslint'
  ],

  extends: [
    // Core JS/TS style
    'eslint:recommended',
    'airbnb-base',
    'plugin:@typescript-eslint/recommended',

    // Security, compat, functional
    'plugin:security/recommended',
    'plugin:compat/recommended',
    'plugin:fp/recommended',

    // Imports, Node, Promises
    'plugin:import/errors',
    'plugin:import/warnings',
    'plugin:import/typescript',
    'plugin:node/recommended',
    'plugin:promise/recommended',

    // Prettier (must come last to override stylistic rules)
    'plugin:prettier/recommended',

    // React
    'plugin:react/recommended'
  ],

  settings: {
    react: { version: 'detect' },
    'import/resolver': {
      node: { extensions: ['.js', '.jsx', '.ts', '.tsx'] },
      typescript: {}  // use tsconfig paths
    }
  },

  rules: {
    // — Prettier: singleQuotes & trailing commas
    'prettier/prettier': ['error', {
      singleQuote: true,
      trailingComma: 'all'
    }],

    // — Airbnb adjustments
    'no-console': ['warn', { allow: ['warn', 'error'] }],
    'import/prefer-default-export': 'off',

    // — TS tweaks
    '@typescript-eslint/explicit-function-return-type': 'warn',
    '@typescript-eslint/no-explicit-any': 'error',

    // — Security
    'security/detect-object-injection': 'error',

    // — FP
    'fp/no-mutation': 'error',

    // — Node
    'node/no-unsupported-features/es-syntax': 'off',

    // …add any other organizational “industry-grade” rules here…
  },

  overrides: [
    {
      files: ['**/*.ts','**/*.tsx'],
      rules: {
        '@typescript-eslint/explicit-module-boundary-types': 'warn'
      }
    },
    {
      files: ['**/*.jsx','**/*.tsx'],
      rules: {
        'react/prop-types': 'off' // we use TS for props validation
      }
    }
  ]
};
