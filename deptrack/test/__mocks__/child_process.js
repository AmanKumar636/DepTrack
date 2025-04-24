// deptrack/test/__mocks__/child_process.js
module.exports = {
  exec: jest.fn((cmd, opts, cb) => cb(null, 'stdout', 'stderr'))
};