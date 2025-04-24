// deptrack/test/extension.test.js
const vscode = require('vscode');
const extension = require('../../src/extension');

describe('DepTrack Extension', () => {
  let context;

  beforeEach(() => {
    // reset all call counts on your spies
    jest.clearAllMocks();

    // a fake extension context
    context = { subscriptions: [] };
  });

  test('activate() registers all commands', () => {
    extension.activate(context);

    // list every command you register in extension.activate
    const commands = [
      'Aman.deptrack.openDashboard',
      'Aman.deptrack.refresh',
      'Aman.deptrack.healthCheck',
      'Aman.deptrack.sendEmail',
      'Aman.deptrack.exportCSV',
      'Aman.deptrack.exportPDF',
      'Aman.deptrack.chat'
    ];

    // assert registerCommand was called for each one
    for (const cmd of commands) {
      expect(vscode.commands.registerCommand).toHaveBeenCalledWith(
        cmd,
        expect.any(Function)
      );
    }
  });

  test('deactivate() does nothing (or your logic)', () => {
    // if you have a deactivate(), call it and assert no error
    expect(() => extension.deactivate()).not.toThrow();
  });
});
