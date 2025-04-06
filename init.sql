-- CREATE ROLE user WITH PASSWORD "2901";
-- ALTER ROLE other_user WITH SUPERUSER;

CREATE TABLE IF NOT EXISTS secret(
    id SERIAL PRIMARY KEY,
    secret_key VARCHAR(512) NOT NULL,
    secret_value VARCHAR(1024),
    passphrase VARCHAR(255),
    ttl_seconds INTEGER
);

CREATE TABLE IF NOT EXISTS logger(
    id SERIAL PRIMARY KEY,
    secret_key VARCHAR(512) NOT NULL,
    action_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action VARCHAR(255),
    ip_address VARCHAR(255)
);