module.exports = {
  require: ['deptrack/test/setup.js'],   // always load this first
  timeout: 60000,
  recursive: true,
  spec: 'deptrack/test/**/*.js'
};