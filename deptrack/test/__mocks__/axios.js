// deptrack/test/__mocks__/axios.js
module.exports = {
  post: jest.fn().mockResolvedValue({ data: { choices: [{ message: { content: 'Mock GPT reply' } }] } }),
  get: jest.fn().mockResolvedValue({ data: {} })
};