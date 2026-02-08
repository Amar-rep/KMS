CREATE TABLE records (
                         record_id VARCHAR(255) PRIMARY KEY,

                         group_id VARCHAR(10) NOT NULL REFERENCES group_keys(group_id) ON DELETE CASCADE,

                         metadata JSONB DEFAULT '{}'::jsonb,

                         created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_records_metadata ON records USING GIN (metadata);