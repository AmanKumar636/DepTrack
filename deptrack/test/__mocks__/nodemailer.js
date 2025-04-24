// deptrack/test/__mocks__/nodemailer.js
module.exports = {
  createTransport: jest.fn().mockReturnValue({
    sendMail: jest.fn().mockResolvedValue({ messageId: 'test-id' })
  })
};