CREATE TABLE group_keys (
                            group_id VARCHAR(10) PRIMARY KEY,
                            group_name VARCHAR(255) NOT NULL,

                            user_public_key BYTEA NOT NULL,

                            dek_base64 TEXT NOT NULL,
                            group_key_base64 TEXT NOT NULL,
                            enc_dek_user TEXT,
                            enc_dek_group TEXT NOT NULL,
                            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
DROP TABLE IF EXISTS group_keys;