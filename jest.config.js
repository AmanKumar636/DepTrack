// jest.config.js
module.exports = {
  preset: 'ts-jest',            // remove or change if you use plain JS
  testEnvironment: 'node',

  // Only run files ending in *.test.js under test/ and include src for coverage
  roots: ['<rootDir>/deptrack/test', '<rootDir>/src'],
  testMatch: ['**/test/**/*.test.js'],

  // Ignore mock definitions when running tests
  testPathIgnorePatterns: ['<rootDir>/deptrack/test/__mocks__'],

  // Map external modules to your manual mocks
  moduleNameMapper: {
    '^vscode$': '<rootDir>/deptrack/test/__mocks__/vscode.js',
    '^nodemailer$': '<rootDir>/deptrack/test/__mocks__/nodemailer.js',
    '^axios$': '<rootDir>/deptrack/test/__mocks__/axios.js',
    '^child_process$': '<rootDir>/deptrack/test/__mocks__/child_process.js',
    '^pdfkit$': '<rootDir>/deptrack/test/__mocks__/pdfkit.js'
  },

  // Coverage settings
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['lcov', 'text']
};