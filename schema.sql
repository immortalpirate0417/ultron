CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'analyst',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    username VARCHAR(50) NULL,
    action VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NULL,
    details VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_action (action),
    INDEX idx_audit_created (created_at)
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    username VARCHAR(50) NULL,
    source_ip VARCHAR(45) NULL,
    destination_ip VARCHAR(45) NULL,
    source_port INT NULL,
    destination_port INT NULL,
    device_id VARCHAR(50) NULL,
    event_type VARCHAR(50) NOT NULL,
    action VARCHAR(50) NULL,
    status VARCHAR(20) NULL,
    resource VARCHAR(255) NULL,
    privilege_level VARCHAR(20) NULL,
    bytes_transferred BIGINT NULL,
    raw_log TEXT NULL,
    severity VARCHAR(10) NOT NULL DEFAULT 'INFO',
    source_type VARCHAR(20) NOT NULL DEFAULT 'synthetic',
    metadata JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_events_time (timestamp),
    INDEX idx_events_user (username),
    INDEX idx_events_ip (source_ip),
    INDEX idx_events_type (event_type)
);

CREATE TABLE IF NOT EXISTS incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    incident_code VARCHAR(20) NULL UNIQUE,
    rule VARCHAR(50) NOT NULL,
    classification VARCHAR(50) NOT NULL,
    affected_user VARCHAR(50) NULL,
    source_ip VARCHAR(45) NULL,
    severity VARCHAR(10) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    summary VARCHAR(255) NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_incidents_status (status),
    INDEX idx_incidents_severity (severity),
    INDEX idx_incidents_dedupe (rule, source_ip, first_seen)
);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id INT NOT NULL,
    event_id BIGINT NOT NULL,
    PRIMARY KEY (incident_id, event_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES security_events(event_id) ON DELETE CASCADE
);