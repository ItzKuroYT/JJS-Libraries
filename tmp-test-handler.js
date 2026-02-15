const handler = require('./api/save-lib');

const req = {
  method: 'GET',
  url: '/api/save-lib',
  headers: {}
};

const res = {
  statusCode: 0,
  headers: {},
  setHeader(key, value){ this.headers[key] = value; },
  status(code){ this.statusCode = code; return this; },
  json(payload){ console.log('status', this.statusCode); console.log('payload', payload); return this; },
  end(){ console.log('end called'); }
};

handler(req, res).then(()=>{
  console.log('done');
}).catch(err=>{
  console.error('handler error', err);
});
