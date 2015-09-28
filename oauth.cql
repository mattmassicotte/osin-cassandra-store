CREATE KEYSPACE oauth WITH REPLICATION = { 'class': 'SimpleStrategy', 'replication_factor': 1 };

CREATE TABLE oauth.clients (
  id TEXT,

  name TEXT,
  secret TEXT,
  redirect_uri TEXT,

  PRIMARY KEY (id)
);

CREATE TABLE oauth.access_grants (
  code TEXT,

  client_id TEXT,
  client_secret TEXT,
  scope TEXT,
  redirect_uri TEXT,
  state TEXT,

  PRIMARY KEY (code)
);

CREATE TABLE oauth.access_tokens (
  code TEXT,

  client_id TEXT,
  client_secret TEXT,
  access_code TEXT,
  access_redirect_uri TEXT,
  access_state TEXT,

  is_refresh BOOLEAN,
  refresh_token TEXT,
  scope TEXT,
  redirect_uri TEXT,
  expired_at INT,

  user_data TEXT,

  PRIMARY KEY (code)
);
