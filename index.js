const url = require('url');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const uuid = require('uuid/v4');
const jsonBody = require('body/json');
const finalhandler = require('finalhandler');
const http = require('http');
const sqlite3 = require('sqlite3');
const Router = require('router');
const config = require('./config.json');

const { secret } = config;

const db = new sqlite3.Database('db/wc2019.db');

// db.serialize(() => {
//   db.run('CREATE TABLE players (id TEXT, name TEXT, password TEXT)');
//   db.run('CREATE TABLE brackets (id TEXT, player_id TEXT, game TEXT, bracket TEXT)')
// })

const router = Router();
router.use((req, res, next) => {
  req.cookieObj = !req.headers.cookie ? {} : req.headers.cookie.split(',').reduce((obj, str) => {
    const [k, v] = str.split('=');
    return {...obj, [k]: v };
  }, {});

  res.setHeader('Access-Control-Allow-Origin', config.frontendOrigin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS, PUT');
  res.setHeader("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  res.setHeader("Access-Control-Allow-Credentials", 'true');
  next();
});


router.options('*', (req, res) => {
  res.statusCode = 200;
  res.end();
});

router.put('/games', (req, res) => {
  jsonBody(req, (err, body) => {
    if (err) { res.statusCode = 400; return; }

    db.run('INSERT INTO games VALUES (?, ?)', uuid(), body.name);
    res.statusCode = 201;
  });
});

router.get('/games/:game_id', (req, res) => {
  res.setHeader('Content-Type', 'text/json');

  db.all('SELECT brackets.*, players.name AS player_name FROM brackets INNER JOIN players ON brackets.player_id = players.id WHERE game = ?', req.params.game_id, (err, data) => {
    if (err) { res.statusCode = 500; res.end('uh oh'); return; }

    res.end(JSON.stringify(data || []));
  });
});

router.post('/logout', (req, res) => {
  res.setHeader('Set-Cookie', [`player=x; Max-Age=0; Domain=${config.frontendDomain}; Path=/`]);
  res.end('cool story');
})

router.post('/login', (req, res) => {
  const succeed = (token, code) => {
    res.setHeader('Set-Cookie', [`player=${token}; Max-Age=10000000; Domain=${config.frontendDomain}; Path=/`]);
    res.statusCode = code;
    res.end(token);
  };

  jsonBody(req, (err, body) => {
    if (err) { res.statusCode = 400; res.end(err); return; }

    db.all('SELECT * FROM players WHERE name = ?', body.name, (err, row) => {
      if (err) { res.statusCode = 500; res.end(err); return; }

      if (row.length === 0) { // create
        bcrypt.hash(body.password, 10, (err, hash) => {
          if (err) { res.statusCode = 500; res.end(err); return; }
          const id = uuid();

          db.run('INSERT INTO players VALUES (?, ?, ?)', id, body.name, hash, (err) => {
            if (err) { res.statusCode = 500; res.end(err); return; }

            succeed(jwt.sign(id, secret), 201);
          });
        });
      }
      else { // verify
        bcrypt.compare(body.password, row[0].password, (err, same) => {
          if (err) { res.statusCode = 500; res.end(err); return; }
          if (!same) { res.statusCode = 422; res.end('bad credentials'); return; }

          succeed(jwt.sign(row[0].id, secret), 200);
        });
      }
    });
  });
});

router.get('/current_player', (req, res) => {
  res.setHeader('Content-Type', 'text/json');
  if (req.cookieObj.player) {
    const player_id = jwt.decode(req.cookieObj.player);

    db.get('SELECT id, name FROM players WHERE players.id = ?', player_id, (err, data) => {
      if (err) { res.statusCode = 500; return; }
      if (!data) { res.setHeader('Set-Cookie', [`player=x; Max-Age=0; Domain=${config.frontendDomain}; Path=/`]); }

      res.end(JSON.stringify(data || null));
    });
  }
  else {
    res.end('null');
  }
});

router.get('/bracket', (req, res) => {
  res.setHeader('Content-Type', 'text/json');
  if (req.cookieObj.player) {
    const query = url.parse(req.url, true).query;
    const game = query ? query.game : null;
    const player_id = jwt.decode(req.cookieObj.player);

    db.get('SELECT * FROM brackets WHERE player_id = ? AND game = ?', player_id, game, (err, data) => {
      if (err) { res.statusCode = 500; res.end('uh oh'); return; }

      res.end(JSON.stringify(data || null));
    });
  }
  else {
    res.statusCode = 200;
    res.end('null');
  }
});

router.post('/join_game', (req, res) => {
  jsonBody(req, (err, body) => {
    if (err) { res.statusCode = 400; return; }

    const game = body.game || null;

    if (req.cookieObj.player && game) {
      const id = uuid();
      const player_id = jwt.decode(req.cookieObj.player);

      db.run('INSERT INTO brackets VALUES (?, ?, ?, ?)', id, player_id, game, '{}', (err, data) => {
        if (err) { res.statusCode = 500; return; }

        db.all('SELECT brackets.*, players.name AS player_name FROM brackets INNER JOIN players ON brackets.player_id = players.id WHERE game = ?', game, (err, data) => {
          if (err) { res.statusCode = 500; res.end('uh oh'); return; }

          res.end(JSON.stringify(data || []));
        });
      });
    }
    else {
      res.statusCode = 401;
      res.end('null');
    }
  });
});

router.patch('/bracket/:bracket_id', (req, res) => {
  res.setHeader('Content-Type', 'text/json');
  jsonBody(req, (err, body) => {
    if (err) { res.statusCode = 400; return; }

    const player_id = jwt.decode(req.cookieObj.player);

    db.run('UPDATE brackets SET bracket = ? WHERE id = ? AND player_id = ?', body.bracket, req.params.bracket_id, player_id, (err, data) => {
      if (err) { res.statusCode = 400; return; }

      db.all(`
        SELECT general.*, players.name AS player_name FROM brackets AS specific
        INNER JOIN brackets as general ON specific.game = general.game
        INNER JOIN players ON specific.player_id = players.id
        WHERE specific.id = ?`,
        req.params.bracket_id, (err, data) => {
          res.end(JSON.stringify(data));
        });
    });
  });
});

const port = 20192;
const server = http.createServer((req, res) => router(req, res, finalhandler(req, res)));

server.listen(port);
console.log(`listening on port ${port}`);
