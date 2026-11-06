-- +goose Up
-- +goose StatementBegin
CREATE TABLE threats (
    md5           VARCHAR(32)  PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    description   TEXT,
    severity      VARCHAR(16),
    type          VARCHAR(32),
    status        VARCHAR(16),
    family        VARCHAR(255),
    source        VARCHAR(255),
    confidence    SMALLINT,
    tags          TEXT[]       NOT NULL DEFAULT '{}',
    sha256        VARCHAR(64),
    file_size     BIGINT,
    file_type     VARCHAR(128),
    first_seen_at TIMESTAMPTZ,
    last_seen_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT threats_md5_format
        CHECK (md5 ~ '^[a-f0-9]{32}$'),

    CONSTRAINT threats_sha256_format
        CHECK (sha256 IS NULL OR sha256 ~ '^[a-f0-9]{64}$'),

    CONSTRAINT threats_severity_enum
        CHECK (severity IS NULL OR severity IN ('low', 'medium', 'high', 'critical')),

    CONSTRAINT threats_type_enum
        CHECK (type IS NULL OR type IN (
            'trojan', 'virus', 'worm', 'ransomware', 'spyware',
            'adware', 'rootkit', 'miner', 'other'
        )),

    CONSTRAINT threats_status_enum
        CHECK (status IS NULL OR status IN (
            'active', 'inactive', 'false_positive', 'archived'
        )),

    CONSTRAINT threats_confidence_range
        CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 100),

    CONSTRAINT threats_file_size_non_negative
        CHECK (file_size IS NULL OR file_size >= 0),

    CONSTRAINT threats_seen_order
        CHECK (
            first_seen_at IS NULL
            OR last_seen_at IS NULL
            OR first_seen_at <= last_seen_at
        )
);

CREATE INDEX threats_severity_idx   ON threats (severity)   WHERE severity IS NOT NULL;
CREATE INDEX threats_status_idx     ON threats (status)     WHERE status IS NOT NULL;
CREATE INDEX threats_name_idx       ON threats (lower(name));
CREATE INDEX threats_created_at_idx ON threats (created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS threats;
-- +goose StatementEnd
