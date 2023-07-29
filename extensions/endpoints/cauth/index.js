const { validateLoginPayload, getAuthMiddleware } = require('./helpers');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');

module.exports = async function registerEndpoint(
  router,
	{ services, logger, env }
) {
  const { ItemsService } = services;
  const authMiddleware = getAuthMiddleware(ItemsService);
  
  router.post('/login', async (req, res) => {
    const payload = req.body;
    
    const validationError = validateLoginPayload(payload);
    if(validationError) {
      res.status(400).json({
        type: 'payload',
        message: validationError
      });
      return;
    }

    const { email, password } = payload;
    const usersService = new ItemsService('cc_users', {
      schema: req.schema
    });
    const sessionsService = new ItemsService('cc_sessions', {
      schema: req.schema
    });

    try {
      const wantedUser = await usersService.readByQuery({
        fields: ['*'],
        filter: {
          email: {
            _eq: email
          }
        }
      });
      if(wantedUser.length === 0) {
        res.status(404).json({
          type: 'not_found',
          message: 'User not found'
        });
        return;
      }
      const user = wantedUser[0];
      if(!user.active) {
        res.status(403).json({
          type: 'inactive',
          message: 'User is inactive'
        });
        return;
      }
      const passwordMatch = await argon2.verify(user.password, password);
      if(!passwordMatch) {
        res.status(403).json({
          type: 'invalid_password',
          message: 'Invalid password'
        });
        return;
      }

      const accessToken = jwt.sign(
        { user_id: user.id, email },
        env.ACCESS_TOKEN_KEY,
        {
          expiresIn: env.ACCESS_TOKEN_TTL,
        }
      );
      const expires = jwt.decode(accessToken).exp * 1000;
      const refreshToken = jwt.sign(
        { user_id: user.id, email },
        env.REFRESH_TOKEN_KEY,
        {
          expiresIn: env.REFRESH_TOKEN_TTL,
        }
      );

      await sessionsService.createOne({
        access_token: accessToken,
        refresh_token: refreshToken,
        expires,
        account: user.id,
      });

      res.status(200).send({
        access_token: accessToken,
        refresh_token: refreshToken,
        expires
      });
    } catch (error) {
      logger.error('Error logging in user');
      console.error(error);
      res.status(500).json({
        type: 'internal',
        message: 'Internal server error'
      });
    }
  });

  router.post('/refresh', async (req, res) => {
    const payload = req.body;
    if(!payload || !payload.refresh_token) {
      res.status(400).json({
        type: 'payload',
        message: 'Missing refresh_token'
      });
      return;
    }
    const sessionsService = new ItemsService('cc_sessions', {
      schema: req.schema
    });
    try {
      const wantedSession = await sessionsService.readByQuery({
        fields: ['*', 'account.*'],
        filter: {
          refresh_token: {
            _eq: payload.refresh_token
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
      const refreshTokenExpires = jwt.decode(payload.refresh_token).exp * 1000;
      if(refreshTokenExpires < new Date().getTime()) {
        res.status(401).json({
          type: 'token_expired',
          message: 'Expired token'
        });
        return;
      }
      const accessToken = jwt.sign(
        { user_id: session.account._id, email: session.account.email },
        env.ACCESS_TOKEN_KEY,
        {
          expiresIn: env.ACCESS_TOKEN_TTL,
        }
      );
      const expires = jwt.decode(accessToken).exp * 1000;
      const refreshToken = jwt.sign(
        { user_id: session.account._id, email: session.account.email },
        env.REFRESH_TOKEN_KEY,
        {
          expiresIn: env.REFRESH_TOKEN_TTL,
        }
      );

      await sessionsService.updateOne(session.id, {
        expires,
        access_token: accessToken,
        refresh_token: refreshToken
      });
      res.status(200).send({
        access_token: accessToken,
        refresh_token: refreshToken,
        expires
      });
    } catch (error) {
      logger.error('Error refreshing token');
      console.error(error);
      res.status(500).json({
        type: 'internal',
        message: 'Internal server error'
      });
    }
  });

  router.post('/logout', authMiddleware, async (req, res) => {
    const payload = req.body;
    const { refresh_token } = payload;
    if(!refresh_token) {
      res.status(400).json({
        type: 'payload',
        message: 'Missing refresh_token'
      });
      return;
    }
    const sessionsService = new ItemsService('cc_sessions', {
      schema: req.schema
    });
    try {
      await sessionsService.deleteByQuery({
        filter: {
          refresh_token: {
            _eq: refresh_token
          }
        }
      });
      res.status(200).send();
    } catch (error) {
      logger.error('Error logging out user');
      console.error(error);
      res.status(500).json({
        type: 'internal',
        message: 'Internal server error'
      });
    }
  });
}