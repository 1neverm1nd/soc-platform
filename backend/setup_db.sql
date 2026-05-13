USE soc_db;

CREATE TABLE IF NOT EXISTS `users` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(100) NOT NULL UNIQUE,
  `email` VARCHAR(255) NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `role` ENUM('user','analyst','admin') NOT NULL DEFAULT 'analyst',
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `incidents` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `raw_log` TEXT NOT NULL,
  `source_ip` VARCHAR(45),
  `destination_ip` VARCHAR(45),
  `ml_type` VARCHAR(100),
  `ml_confidence` FLOAT,
  `analyst_label` VARCHAR(100),
  `severity` ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  `status` ENUM('open','investigating','resolved','false_positive') NOT NULL DEFAULT 'open',
  `threat_country` VARCHAR(100),
  `abuse_score` INT,
  `mitre_id` VARCHAR(20),
  `mitre_technique` VARCHAR(200),
  `mitre_tactic` VARCHAR(100),
  `ai_analysis` JSON,
  `analyst_notes` TEXT,
  `campaign_id` INT,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_source_ip` (`source_ip`),
  INDEX `idx_status` (`status`),
  INDEX `idx_severity` (`severity`),
  INDEX `idx_created_at` (`created_at`)
);

CREATE TABLE IF NOT EXISTS `blocked_ips` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `ip_address` VARCHAR(45) NOT NULL UNIQUE,
  `reason` TEXT,
  `blocked_by` INT,
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `expires_at` TIMESTAMP NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id` BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT,
  `action` VARCHAR(100) NOT NULL,
  `entity_type` VARCHAR(50),
  `entity_id` INT,
  `details` JSON,
  `ip_address` VARCHAR(45),
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `response_rules` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(200) NOT NULL,
  `description` TEXT,
  `is_enabled` BOOLEAN NOT NULL DEFAULT TRUE,
  `priority` INT NOT NULL DEFAULT 50,
  `condition_type` VARCHAR(100),
  `condition_min_severity` ENUM('low','medium','high','critical'),
  `condition_min_confidence` FLOAT,
  `condition_ip_pattern` VARCHAR(255),
  `actions` JSON NOT NULL,
  `trigger_count` INT NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `response_playbooks` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(200) NOT NULL,
  `description` TEXT,
  `incident_type` VARCHAR(100),
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `execution_count` INT NOT NULL DEFAULT 0,
  `avg_execution_time` FLOAT,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `playbook_actions` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `playbook_id` INT NOT NULL,
  `sequence` INT NOT NULL,
  `action_type` VARCHAR(100) NOT NULL,
  `action_params` JSON,
  `description` TEXT,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `notifications` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `type` ENUM('critical_incident','escalation','status_change','false_positive') NOT NULL,
  `title` VARCHAR(500) NOT NULL,
  `message` TEXT NOT NULL,
  `incident_id` INT,
  `is_read` BOOLEAN NOT NULL DEFAULT FALSE,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `notification_templates` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(200) NOT NULL,
  `type` VARCHAR(100) NOT NULL,
  `lang` ENUM('en','ru','kk') NOT NULL DEFAULT 'en',
  `title_template` VARCHAR(500) NOT NULL,
  `body_template` TEXT NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `user_notification_preferences` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL UNIQUE,
  `email_enabled` BOOLEAN NOT NULL DEFAULT TRUE,
  `in_app_enabled` BOOLEAN NOT NULL DEFAULT TRUE,
  `min_severity` ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  `quiet_hours_start` INT,
  `quiet_hours_end` INT,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `escalation_policies` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(200) NOT NULL,
  `incident_type` VARCHAR(100),
  `min_severity` ENUM('low','medium','high','critical') NOT NULL DEFAULT 'high',
  `timeout_minutes` INT NOT NULL DEFAULT 30,
  `action` ENUM('notify_manager','page_oncall','escalate_severity') NOT NULL,
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `response_action_logs` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `incident_id` INT,
  `playbook_id` INT,
  `rule_id` INT,
  `action_type` VARCHAR(100) NOT NULL,
  `action_params` JSON,
  `status` ENUM('success','failed','pending') NOT NULL DEFAULT 'pending',
  `result` TEXT,
  `execution_time` INT,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS `attack_campaigns` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `source_ip` VARCHAR(45) NOT NULL UNIQUE,
  `incident_count` INT NOT NULL DEFAULT 1,
  `severity` ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
  `attack_types` JSON,
  `first_seen` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_seen` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE
);

-- Seed default rules
INSERT IGNORE INTO `response_rules` (`name`, `description`, `priority`, `condition_type`, `condition_min_severity`, `actions`, `is_enabled`) VALUES
('Auto-Block Malware IPs', 'Automatically block IPs sending malware', 10, 'malware', 'high', '[{"type":"block_ip"},{"type":"notify"}]', TRUE),
('Escalate Critical Incidents', 'Escalate all critical severity incidents', 20, NULL, 'critical', '[{"type":"escalate"},{"type":"notify"}]', TRUE),
('SQL Injection Alert', 'Notify on SQL injection attempts', 30, 'sql-injection', 'medium', '[{"type":"notify"}]', TRUE),
('DDoS Auto-Response', 'Block and escalate DDoS attacks', 15, 'ddos', 'high', '[{"type":"block_ip"},{"type":"escalate"}]', TRUE);

-- Seed default playbook
INSERT IGNORE INTO `response_playbooks` (`id`, `name`, `description`, `incident_type`, `is_active`) VALUES
(1, 'Malware Response', 'Standard malware incident response procedure', 'malware', TRUE),
(2, 'Data Breach Response', 'Response to data exfiltration incidents', 'data-exfiltration', TRUE);

INSERT IGNORE INTO `playbook_actions` (`playbook_id`, `sequence`, `action_type`, `description`, `action_params`) VALUES
(1, 1, 'isolate_host', 'Isolate affected host from network', '{"host":"affected-host"}'),
(1, 2, 'collect_forensics', 'Collect forensic evidence', '{}'),
(1, 3, 'notify_team', 'Notify security team', '{"channel":"in-app"}'),
(1, 4, 'scan_network', 'Scan network for further infection', '{}'),
(2, 1, 'block_ip', 'Block exfiltration destination IP', '{}'),
(2, 2, 'collect_forensics', 'Collect forensic data on exfiltrated files', '{}'),
(2, 3, 'notify_team', 'Alert incident response team', '{"channel":"in-app"}');

-- Seed escalation policy
INSERT IGNORE INTO `escalation_policies` (`name`, `min_severity`, `timeout_minutes`, `action`, `is_active`) VALUES
('Critical Incident Escalation', 'critical', 15, 'notify_manager', TRUE),
('High Severity Timeout', 'high', 60, 'escalate_severity', TRUE);
