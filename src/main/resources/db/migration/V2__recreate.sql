
CREATE TABLE users (
                       id SERIAL PRIMARY KEY,

                       user_id_keccak VARCHAR(64) UNIQUE NOT NULL,


                       public_key BYTEA UNIQUE NOT NULL,

                       name VARCHAR(255),
                       physical_address TEXT,
                       phone VARCHAR(20),
                       created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);





CREATE TABLE group_keys (
                            group_id VARCHAR(10) PRIMARY KEY,
                            group_name VARCHAR(255) NOT NULL,


                            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,

                            dek_base64 TEXT NOT NULL,
                            group_key_base64 TEXT NOT NULL,


                            enc_dek_user TEXT,


                            enc_dek_group TEXT NOT NULL,

                            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


CREATE INDEX idx_group_keys_user_id ON group_keys(user_id);