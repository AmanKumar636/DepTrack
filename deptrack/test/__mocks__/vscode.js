// deptrack/test/__mocks__/vscode.js
module.exports = {
  commands: {
    registerCommand: jest.fn(),
    executeCommand: jest.fn()
  },
  window: {
    createOutputChannel: jest.fn().mockReturnValue({
      append: jest.fn(),
      appendLine: jest.fn(),
      show: jest.fn(),
      clear: jest.fn(),
      dispose: jest.fn()
    }),
    showInformationMessage: jest.fn(),
    showErrorMessage: jest.fn()
  },
  workspace: {
    getConfiguration: jest.fn()
  }
};