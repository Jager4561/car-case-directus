function validateLoginPayload(payload) {
  if(!payload) {
    return 'Missing payload';
  }
  if(!payload.email ) {
    return 'Missing email';
  }
  if(!payload.password) {
    return 'Missing password';
  }
  const emailRegex = /^[A-Za-z0-9_!#$%&'*+\/=?`{|}~^.-]+@[A-Za-z0-9.-]+$/gm;
  if(!emailRegex.test(payload.email)) {
    return 'Invalid email';
  }
  if(payload.password.length < 8) {
    return 'Password must be at least 8 characters long';
  }
  return null;
};

function getAuthMiddleware(ItemsService) {
  return async function authMiddleware(req, res, next) {
    const { authorization } = req.headers;
    if(!authorization) {
      res.status(400).json({
        type: 'token_missing',
        message: 'Missing authorization header'
      });
      return;
    }
    const [authType, token] = authorization.split(' ');
    if(authType !== 'Bearer') {
      res.status(401).json({
        type: 'token_invalid',
        message: 'Invalid authorization header'
      });
      return;
    }
    const sessionsService = new ItemsService('cc_sessions', {
      schema: req.schema
    });
    const wantedSession = await sessionsService.readByQuery({
      fields: ['*', 'account.*'],
      filter: {
        access_token: {
          _eq: token
        }
      }
    });
    if(wantedSession.length === 0) {
      res.status(401).json({
        type: 'unauthorized',
        message: 'Invalid token'
      });
      return;
    }
    const session = wantedSession[0];
    if(session.expires_at < new Date()) {
      res.status(401).json({
        type: 'token_expired',
        message: 'Expired token'
      });
      return;
    }
    req.user = session.account;
    next();
  };
}

module.exports = {
  validateLoginPayload,
  getAuthMiddleware
};