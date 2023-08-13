module.exports = async function registerEndpoint(
  router,
	{ services, logger, env }
) {

  const mailTemplates = [
    'activate',
    'reset-password',
  ]

  const { MailService } = services;

  router.post('/', async (req, res) => {
    const payload = req.body;
    if(!payload) {
      console.log('Missing payload');
      return res.status(400).send('Missing payload');
    }
    if(!payload.token) {
      console.log('Missing token');
      return res.status(400).send('Missing token');
    }
    if(!payload.template) {
      console.log('Missing template');
      return res.status(400).send('Missing template');
    }
    if(!mailTemplates.includes(payload.template.name)) {
      console.log('Invalid template');
      return res.status(400).send('Invalid template');
    }
    if(!payload.to) {
      console.log('Missing to');
      return res.status(400).send('Missing to');
    }
    if(!payload.subject) {
      console.log('Missing subject');
      return res.status(400).send('Missing subject');
    }
    if(!payload.template.data) {
      console.log('Missing body');
      return res.status(400).send('Missing body');
    }

    const token = payload.token;
    if(token !== env.MAIL_TOKEN) {
      return res.status(401).send('Invalid token');
    }

    const mailService = new MailService({
      schema: req.schema
    });

    try {
      await mailService.send({
        to: payload.to,
        subject: payload.subject,
        template: {
          name: payload.template.name,
          data: payload.template.data,
        }
      });
      return res.status(200).send('OK');
    } catch (error) {
      logger.error('Error sending mail');
      console.error(error);
      return res.status(500).send('Internal error');
    }
  });
}