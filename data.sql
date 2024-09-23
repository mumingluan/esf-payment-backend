CREATE TABLE esf_payment_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    balance DECIMAL(10, 2) DEFAULT 0,
    token VARCHAR(255)
);

CREATE TABLE esf_payment_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45),
    operation VARCHAR(255),
    timestamp DATETIME
);
