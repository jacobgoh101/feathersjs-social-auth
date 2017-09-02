const authentication = require('feathers-authentication');
const jwt = require('feathers-authentication-jwt');
const CustomStrategy = require('passport-custom');
const verifySocialToken = require('./utility/verifySocialToken');

module.exports = function () {
  const app = this;
  const config = app.get('authentication');

  // Set up authentication with the secret
  app.configure(authentication(config));
  app.configure(jwt());

  // custom passport strategy for client side social login
  app
    .passport
    .use('social-token', new CustomStrategy(async(req, callback) => {
      // Do your custom user finding logic here, or set to false based on req object
      try {
        // this is what client send to server
        const {email, socialId, socialToken} = req.body;

        // verify social id and token
        verifySocialToken(socialId, socialToken);

        // find user
        let users = await app
          .service('users')
          .find({query: {
              email
            }});
        let user = null;
        if (!users.total) {
          // user does not exist yet, create new user
          user = await app
            .service('users')
            .create({email});
        } else {
          user = users.data[0];
        }

        callback(null, user);
      } catch (err) {
        callback(err, false);
      }
    }));

  // The `authentication` service is used to create a JWT. The before `create`
  // hook registers strategies that can be used to create a new valid JWT (e.g.
  // local or oauth2)
  app
    .service('authentication')
    .hooks({
      before: {
        create: [
          authentication
            .hooks
            .authenticate(config.strategies),
          // This hook adds userId attribute to the JWT payload
          (hook) => {
            if (!(hook.params.authenticated)) 
              return;
            
            const user = hook.params.user;
            // make sure params.payload exists
            hook.params.payload = hook.params.payload || {}
            // merge in a `userId` property
            Object.assign(hook.params.payload, {userId: user._id})
          }
        ],
        remove: [
          authentication
            .hooks
            .authenticate('jwt')
        ]
      }
    });
};
