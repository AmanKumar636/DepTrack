// deptrack/test/__mocks__/pdfkit.js
module.exports = jest.fn().mockImplementation(() => ({
  pipe: jest.fn(),
  text: jest.fn(),
  end: jest.fn()
}));