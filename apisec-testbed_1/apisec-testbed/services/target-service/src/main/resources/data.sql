MERGE INTO users  KEY(id) VALUES (1,'alice','alice123','ROLE_USER');
MERGE INTO users  KEY(id) VALUES (2,'bob','bob123','ROLE_USER');
MERGE INTO users  KEY(id) VALUES (3,'admin','admin123','ROLE_ADMIN');

MERGE INTO products KEY(id) VALUES (1,'Roteador Wi-Fi 6',899.90,'redes');
MERGE INTO products KEY(id) VALUES (2,'Switch 24 portas',1299.00,'redes');
MERGE INTO products KEY(id) VALUES (3,'Firewall UTM',4590.00,'seguranca');
MERGE INTO products KEY(id) VALUES (4,'Token OTP',129.90,'seguranca');
MERGE INTO products KEY(id) VALUES (5,'Cabo Cat6 305m',749.00,'cabeamento');

MERGE INTO orders KEY(id) VALUES (1,'alice','Firewall UTM',4590.00,'4242');
MERGE INTO orders KEY(id) VALUES (2,'bob','Roteador Wi-Fi 6',899.90,'1881');
MERGE INTO orders KEY(id) VALUES (3,'alice','Token OTP',129.90,'4242');
MERGE INTO orders KEY(id) VALUES (4,'admin','Switch 24 portas',1299.00,'0007');
