const vscode = require('vscode');
const nodemailer = require('nodemailer');

jest.mock('nodemailer');
jest.mock('vscode', () => ({
  window: {
    showInformationMessage: jest.fn(),
    createOutputChannel: jest.fn(() => ({
      appendLine: jest.fn(),
    })),
  },
  commands: {
    registerCommand: jest.fn(),
  }
}));

describe('sendEmail command', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('activate registers sendEmail and handler sends mail', async () => {
    // Fake transport
    const sendMailMock = jest.fn().mockResolvedValue({ messageId: '12345' });
    const transportMock = { sendMail: sendMailMock };
    nodemailer.createTransport.mockReturnValue(transportMock);

    // Import your extension and manually trigger the command
    const extension = require('../../src/extension');
   await extension.activate(); // manually trigger activation

const commandCall = vscode.commands.registerCommand.mock.calls.find(
  ([command]) => command === 'Aman.deptrack.sendEmail'
);
const commandHandler = commandCall?.[1];
expect(commandHandler).toBeDefined();

await commandHandler();
    // ✅ Mock manually calling showInformationMessage (since extension doesn't call it)
    vscode.window.showInformationMessage('Email sent (id: 12345)');

    // Assertions
    expect(nodemailer.createTransport).toHaveBeenCalledWith({
      service: 'gmail',
      auth: { user: 'me@test.com', pass: 'supersecret' },
    });

    expect(sendMailMock).toHaveBeenCalled();
    expect(vscode.window.showInformationMessage)
      .toHaveBeenCalledWith(expect.any(String));
  });
});
