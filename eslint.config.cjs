// ─── eslint.config.cjs ─────────────────────────────────────────────────────
const path           = require("path");
const { FlatCompat } = require("@eslint/eslintrc");
const js             = require("@eslint/js");
const parser         = require("@typescript-eslint/parser");
const security       = require("eslint-plugin-security");

// __dirname is native in CommonJS modules
const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended
});

module.exports = [
  // 0) Globals + React version detection
  {
    languageOptions: {
      globals: {
        console:  "readonly",
        window:   "readonly",
        document: "readonly",
        process:  "readonly"
      }
    },
    settings: {
      react: { version: "detect" }
    }
  },

  // 1) Legacy shareables → flat
  ...compat.extends(
    "eslint:recommended",
    "plugin:import/recommended",
    "plugin:import/warnings",
    "plugin:import/typescript",
    "plugin:react/recommended",
    "plugin:jsx-a11y/recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:prettier/recommended"
  ),

  // 2) ESLint core recommended (flat)
  js.configs.recommended,

  // 3) Security plugin flat-config (manual injection)
  security.configs.recommended,

  // 4) Your custom overrides
  {
    files: ["**/*.{js,jsx,ts,tsx}"],
    languageOptions: {
      parser,
      parserOptions: {
        ecmaVersion: 2020,
        sourceType: "module"
      }
    },
    rules: {
      // Semicolons are still your preference; Prettier’s already enabled above
      semi: ["error", "always"]
    }
  }
];


