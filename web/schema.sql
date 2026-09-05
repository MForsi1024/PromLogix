CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(190) NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','customer') NOT NULL DEFAULT 'customer',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    activation_token VARCHAR(190) NULL UNIQUE,
    activation_expires_at DATETIME NULL,
    last_login_at DATETIME NULL,
    password_changed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS access_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    email VARCHAR(190) NOT NULL,
    organization VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    password_hash VARCHAR(255) NULL,
    status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
    admin_comment TEXT NULL,
    submit_ip_hash CHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at DATETIME NULL,
    INDEX idx_access_status (status),
    INDEX idx_access_email (email),
    INDEX idx_access_ip (submit_ip_hash, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS edge_gateways (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    edge_id VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    last_seen_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS locations (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    marker_id INT NULL,
    kind ENUM('base','delivery','service') NOT NULL DEFAULT 'delivery',
    x DECIMAL(8,2) NOT NULL DEFAULT 0,
    y DECIMAL(8,2) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS facility_maps (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version INT UNSIGNED NOT NULL DEFAULT 1,
    map_json LONGTEXT NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS robots (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    robot_uid VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    edge_gateway_id BIGINT UNSIGNED NOT NULL,
    current_location_id BIGINT UNSIGNED NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'idle',
    battery_percent INT NULL,
    telemetry_status VARCHAR(50) NOT NULL DEFAULT 'offline',
    last_robot_seen_at DATETIME NULL,
    robot_access_key_encrypted TEXT NULL,
    robot_key_version INT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_robot_edge FOREIGN KEY (edge_gateway_id) REFERENCES edge_gateways(id),
    CONSTRAINT fk_robot_location FOREIGN KEY (current_location_id) REFERENCES locations(id) ON DELETE SET NULL,
    INDEX idx_robot_edge (edge_gateway_id),
    INDEX idx_robot_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS robot_assignments (
    user_id BIGINT UNSIGNED NOT NULL,
    robot_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, robot_id),
    CONSTRAINT fk_assignment_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_assignment_robot FOREIGN KEY (robot_id) REFERENCES robots(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS recipients (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(255) NOT NULL,
    department VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_recipient_name (full_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rfid_cards (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    uid VARCHAR(100) NULL,
    uid_hash CHAR(64) NULL UNIQUE,
    uid_encrypted TEXT NULL,
    uid_mask VARCHAR(32) NOT NULL DEFAULT '••••',
    label VARCHAR(255) NOT NULL,
    recipient_id BIGINT UNSIGNED NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_card_recipient FOREIGN KEY (recipient_id) REFERENCES recipients(id) ON DELETE CASCADE,
    INDEX idx_card_recipient (recipient_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS missions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    mission_uid CHAR(36) NOT NULL UNIQUE,
    robot_id BIGINT UNSIGNED NOT NULL,
    customer_id BIGINT UNSIGNED NOT NULL,
    pickup_location_id BIGINT UNSIGNED NOT NULL,
    destination_location_id BIGINT UNSIGNED NOT NULL,
    base_location_id BIGINT UNSIGNED NOT NULL,
    cargo_description TEXT NOT NULL,
    shipment_type ENUM('standard','oversized','mixed') NOT NULL DEFAULT 'standard',
    sender_name VARCHAR(255) NOT NULL DEFAULT '',
    recipient_name VARCHAR(255) NOT NULL DEFAULT '',
    status VARCHAR(80) NOT NULL DEFAULT 'created',
    version INT UNSIGNED NOT NULL DEFAULT 1,
    last_event_sequence BIGINT UNSIGNED NOT NULL DEFAULT 0,
    pin_hash VARCHAR(255) NOT NULL,
    pin_encrypted TEXT NOT NULL,
    rfid_verifier_key_encrypted TEXT NULL,
    cancel_requested_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    completed_at DATETIME NULL,
    CONSTRAINT fk_mission_robot FOREIGN KEY (robot_id) REFERENCES robots(id),
    CONSTRAINT fk_mission_customer FOREIGN KEY (customer_id) REFERENCES users(id),
    CONSTRAINT fk_mission_pickup FOREIGN KEY (pickup_location_id) REFERENCES locations(id),
    CONSTRAINT fk_mission_destination FOREIGN KEY (destination_location_id) REFERENCES locations(id),
    CONSTRAINT fk_mission_base FOREIGN KEY (base_location_id) REFERENCES locations(id),
    INDEX idx_mission_robot (robot_id),
    INDEX idx_mission_customer (customer_id),
    INDEX idx_mission_status (status),
    INDEX idx_mission_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mission_rfid (
    mission_id BIGINT UNSIGNED NOT NULL,
    rfid_card_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (mission_id, rfid_card_id),
    CONSTRAINT fk_mission_rfid_mission FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
    CONSTRAINT fk_mission_rfid_card FOREIGN KEY (rfid_card_id) REFERENCES rfid_cards(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mission_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_uid VARCHAR(100) NOT NULL UNIQUE,
    mission_id BIGINT UNSIGNED NOT NULL,
    sequence_number BIGINT UNSIGNED NULL,
    event_type VARCHAR(100) NOT NULL,
    source ENUM('cloud','edge','robot') NOT NULL,
    payload_json LONGTEXT NOT NULL,
    occurred_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_event_mission FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
    INDEX idx_event_mission_time (mission_id, occurred_at),
    UNIQUE KEY uq_event_mission_sequence (mission_id, sequence_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS edge_commands (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    command_uid CHAR(36) NOT NULL UNIQUE,
    edge_gateway_id BIGINT UNSIGNED NOT NULL,
    mission_id BIGINT UNSIGNED NULL,
    command_type VARCHAR(100) NOT NULL,
    payload_json LONGTEXT NOT NULL,
    status ENUM('pending','acked','rejected','cancelled','expired') NOT NULL DEFAULT 'pending',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    acked_at DATETIME NULL,
    CONSTRAINT fk_command_edge FOREIGN KEY (edge_gateway_id) REFERENCES edge_gateways(id),
    CONSTRAINT fk_command_mission FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,
    INDEX idx_command_edge_status (edge_gateway_id, status, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rate_limits (
    bucket_key CHAR(64) PRIMARY KEY,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    window_started_at DATETIME NOT NULL,
    blocked_until DATETIME NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(80) NULL,
    entity_id VARCHAR(100) NULL,
    ip_hash CHAR(64) NULL,
    details_json LONGTEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_audit_created (created_at),
    INDEX idx_audit_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_id VARCHAR(100) PRIMARY KEY,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
