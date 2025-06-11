CREATE TABLE orders (
         id SERIAL PRIMARY KEY,
         item VARCHAR(255) NOT NULL,
         quantity INTEGER NOT NULL,
         site_id VARCHAR(50) NOT NULL,
         status VARCHAR(50) NOT NULL,
         timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
         supplier VARCHAR(255),
         expected_delivery DATE
     );

     CREATE TABLE incidents (
         id SERIAL PRIMARY KEY,
         type VARCHAR(50) NOT NULL,
         description TEXT NOT NULL,
         severity VARCHAR(50) NOT NULL,
         date DATE NOT NULL,
         reported_by VARCHAR(100),
         actions_taken TEXT,
         status VARCHAR(50) DEFAULT 'Open'
     );

     CREATE TABLE tasks (
         id SERIAL PRIMARY KEY,
         title VARCHAR(255) NOT NULL,
         assigned_to VARCHAR(100) NOT NULL,
         status VARCHAR(50) NOT NULL,
         due_date DATE NOT NULL,
         description TEXT,
         progress INTEGER DEFAULT 0,
         assigned_on DATE DEFAULT CURRENT_DATE
     );

     CREATE TABLE equipment (
         id VARCHAR(10) PRIMARY KEY,
         name VARCHAR(100) NOT NULL,
         site VARCHAR(50) NOT NULL,
         status VARCHAR(50) NOT NULL,
         last_maintenance DATE NOT NULL,
         next_maintenance DATE,
         usage_hours INTEGER,
         operator VARCHAR(100)
     );