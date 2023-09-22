SET GLOBAL innodb_file_per_table = on;
SET GLOBAL innodb_default_row_format = dynamic;
DROP TABLE IF EXISTS file_monitoring;
CREATE DATABASE IF NOT EXISTS overwatch;
USER overwatch;

CREATE TABLE file_monitoring (
                                 path VARCHAR(2048) NOT NULL,
                                 hash VARCHAR(255) NOT NULL,
                                 inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                 PRIMARY KEY (path(100), hash)
);

DROP TABLE IF EXISTS file_monitoring_conflicts;
CREATE TABLE file_monitoring_conflicts (
                                           path VARCHAR(2048) NOT NULL,
                                           new_hash VARCHAR(255),
                                           old_hash VARCHAR(255),
                                           checked boolean DEFAULT false
);

DROP TABLE IF EXISTS suspicious_process;
CREATE TABLE suspicious_process (
                                    inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                    pid INT NOT NULL,
                                    cmd_line TEXT,
                                    suspicion_type TEXT CHECK( suspicion_type IN ('network', 'file')),
                                    data TEXT
);

DROP TABLE IF EXISTS virus_detected;
CREATE TABLE virus_detected (
                                inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                path VARCHAR(2048) NOT NULL,
                                cause VARCHAR(255) NOT NULL,
                                PRIMARY KEY (path(100), cause)
);