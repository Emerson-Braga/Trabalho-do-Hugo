CREATE TABLE IF NOT EXISTS users (
  id       INT PRIMARY KEY,
  username VARCHAR(64) UNIQUE NOT NULL,
  password VARCHAR(128) NOT NULL,
  role     VARCHAR(32)  NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
  id       INT PRIMARY KEY,
  name     VARCHAR(128) NOT NULL,
  price    DECIMAL(10,2) NOT NULL,
  category VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS orders (
  id         INT PRIMARY KEY,
  owner      VARCHAR(64)  NOT NULL,
  item       VARCHAR(128) NOT NULL,
  total      DECIMAL(10,2) NOT NULL,
  card_last4 VARCHAR(4)
);
